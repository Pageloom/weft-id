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
        assert meta.end_session_endpoint == "https://acme.example.com/oauth2/logout"

    def test_trailing_slash_on_issuer_is_normalized(self):
        meta = discovery_service.build_discovery_metadata("https://acme.example.com/")
        assert meta.issuer == "https://acme.example.com"
        assert meta.token_endpoint == "https://acme.example.com/oauth2/token"

    def test_static_capability_values(self):
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.subject_types_supported == ["public"]
        assert meta.id_token_signing_alg_values_supported == ["RS256"]
        assert meta.response_types_supported == ["code"]
        assert meta.response_modes_supported == ["query", "form_post"]
        assert "authorization_code" in meta.grant_types_supported

    def test_frontchannel_logout_with_session_advertised(self):
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.frontchannel_logout_supported is True
        assert meta.frontchannel_logout_session_supported is True
        assert "sid" in meta.claims_supported

    def test_backchannel_logout_with_session_advertised(self):
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.backchannel_logout_supported is True
        assert meta.backchannel_logout_session_supported is True

    def test_claims_parameter_explicitly_unsupported(self):
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.claims_parameter_supported is False
        assert meta.model_dump()["claims_parameter_supported"] is False

    def test_scopes_track_shared_assembler(self):
        """scopes_supported is sourced from the shared assembler so the two
        can never drift; `groups` joined SUPPORTED_SCOPES in Iteration 4."""
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.scopes_supported == list(claims_service.SUPPORTED_SCOPES)
        assert "groups" in meta.scopes_supported

    def test_claims_supported_include_envelope_and_scope_claims(self):
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        claims = set(meta.claims_supported)
        assert {"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid"} <= claims
        assert {"name", "email", "email_verified", "zoneinfo"} <= claims
        assert "groups" in claims

    def test_request_objects_are_signed_only(self):
        """Signed request objects by value and by reference; "none" is never
        advertised, and a request_uri must be registered."""
        meta = discovery_service.build_discovery_metadata("https://t.example.com")
        assert meta.request_parameter_supported is True
        assert meta.request_uri_parameter_supported is True
        assert meta.require_request_uri_registration is True
        assert "none" not in meta.request_object_signing_alg_values_supported
        assert meta.userinfo_signing_alg_values_supported == ["RS256"]

    def test_registration_endpoint_only_when_enabled(self):
        assert (
            discovery_service.build_discovery_metadata(
                "https://t.example.com"
            ).registration_endpoint
            is None
        )
        meta = discovery_service.build_discovery_metadata(
            "https://t.example.com/", registration_enabled=True
        )
        assert meta.registration_endpoint == "https://t.example.com/oauth2/register"
