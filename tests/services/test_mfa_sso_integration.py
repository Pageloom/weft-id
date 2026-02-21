"""Tests for SSO context preservation through MFA and SAML auth flows."""

from routers.saml_idp._helpers import extract_pending_sso, get_post_auth_redirect

# ============================================================================
# extract_pending_sso
# ============================================================================


class TestExtractPendingSso:
    def test_returns_dict_when_present(self):
        session = {
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "https://app.com",
            "pending_sso_sp_name": "Test App",
            "other_key": "ignored",
        }
        result = extract_pending_sso(session)
        assert result is not None
        assert result["pending_sso_sp_entity_id"] == "https://sp.example.com"
        assert result["pending_sso_authn_request_id"] == "_req123"
        assert result["pending_sso_relay_state"] == "https://app.com"
        assert result["pending_sso_sp_name"] == "Test App"
        assert "other_key" not in result

    def test_returns_none_when_no_sp_entity_id(self):
        session = {"user_id": "some-user"}
        result = extract_pending_sso(session)
        assert result is None

    def test_returns_none_for_empty_session(self):
        result = extract_pending_sso({})
        assert result is None

    def test_handles_missing_optional_keys(self):
        session = {
            "pending_sso_sp_entity_id": "https://sp.example.com",
        }
        result = extract_pending_sso(session)
        assert result is not None
        assert result["pending_sso_sp_entity_id"] == "https://sp.example.com"
        assert result["pending_sso_authn_request_id"] == ""


# ============================================================================
# get_post_auth_redirect
# ============================================================================


class TestGetPostAuthRedirect:
    def test_returns_consent_when_sso_pending(self):
        session = {"pending_sso_sp_entity_id": "https://sp.example.com"}
        assert get_post_auth_redirect(session) == "/saml/idp/consent"

    def test_returns_default_when_no_sso(self):
        session = {"user_id": "some-user"}
        assert get_post_auth_redirect(session) == "/dashboard"

    def test_returns_custom_default(self):
        session = {}
        assert get_post_auth_redirect(session, default="/custom") == "/custom"

    def test_returns_consent_even_with_custom_default(self):
        session = {"pending_sso_sp_entity_id": "https://sp.example.com"}
        assert get_post_auth_redirect(session, default="/custom") == "/saml/idp/consent"
