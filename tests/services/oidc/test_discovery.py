"""Unit tests for OIDC discovery metadata assembly (services/oidc/discovery.py)."""

from services.oidc import claims as claims_service
from services.oidc import discovery as discovery_service


class TestBuildDiscoveryMetadata:
    def test_endpoints_derive_from_issuer(self):
        meta = discovery_service.build_discovery_metadata("https://acme.example.com")
        assert meta.issuer == "https://acme.example.com"
        assert meta.authorization_endpoint == "https://acme.example.com/oauth2/authorize"
        assert meta.token_endpoint == "https://acme.example.com/oauth2/token"
        assert meta.userinfo_endpoint == "https://acme.example.com/userinfo"
        assert meta.jwks_uri == "https://acme.example.com/.well-known/jwks.json"

    def test_trailing_slash_on_issuer_is_normalized(self):
        meta = discovery_service.build_discovery_metadata("https://acme.example.com/")
        assert meta.issuer == "https://acme.example.com"
        assert meta.token_endpoint == "https://acme.example.com/oauth2/token"

    def test_static_capability_values(self):
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.subject_types_supported == ["public"]
        assert meta.id_token_signing_alg_values_supported == ["RS256"]
        assert meta.response_types_supported == ["code"]
        assert "authorization_code" in meta.grant_types_supported

    def test_scopes_track_shared_assembler(self):
        """scopes_supported is sourced from the shared assembler so the two
        can never drift; `groups` joined SUPPORTED_SCOPES in Iteration 4."""
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.scopes_supported == list(claims_service.SUPPORTED_SCOPES)
        assert "groups" in meta.scopes_supported

    def test_claims_supported_include_envelope_and_scope_claims(self):
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        claims = set(meta.claims_supported)
        assert {"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"} <= claims
        assert {"name", "email", "email_verified"} <= claims
        assert "groups" in claims
