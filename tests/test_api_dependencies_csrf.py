"""Tests for CSRF validation in api_dependencies.py.

Covers the _validate_session_csrf helper and its integration with
get_current_user_api when the session-cookie auth path is used.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

# ---------------------------------------------------------------------------
# Unit tests for _validate_session_csrf
# ---------------------------------------------------------------------------


def _make_request(method: str, session_token=None, header_token=None) -> MagicMock:
    """Build a minimal mock Request for _validate_session_csrf."""
    request = MagicMock()
    request.method = method
    request.session = {}
    if session_token is not None:
        request.session["_csrf_token"] = session_token
    request.headers = MagicMock()
    request.headers.get = lambda key, default=None: (
        header_token if key == "X-CSRF-Token" else default
    )
    return request


class TestValidateSessionCsrf:
    """Unit tests for _validate_session_csrf."""

    def setup_method(self):
        from api_dependencies import _validate_session_csrf

        self._fn = _validate_session_csrf

    def test_get_is_exempt(self):
        """GET requests are exempt from CSRF validation."""
        request = _make_request("GET")
        # Should not raise
        self._fn(request)

    def test_head_is_exempt(self):
        """HEAD requests are exempt from CSRF validation."""
        request = _make_request("HEAD")
        self._fn(request)

    def test_options_is_exempt(self):
        """OPTIONS requests are exempt from CSRF validation."""
        request = _make_request("OPTIONS")
        self._fn(request)

    def test_post_no_session_token_raises_403(self):
        """POST with no session CSRF token raises 403."""
        request = _make_request("POST", session_token=None, header_token=None)
        with pytest.raises(HTTPException) as exc_info:
            self._fn(request)
        assert exc_info.value.status_code == 403
        assert "required" in exc_info.value.detail

    def test_post_session_token_missing_header_raises_403(self):
        """POST with session token but no header raises 403."""
        request = _make_request("POST", session_token="abc123", header_token=None)
        with pytest.raises(HTTPException) as exc_info:
            self._fn(request)
        assert exc_info.value.status_code == 403
        assert "required" in exc_info.value.detail

    def test_post_mismatched_token_raises_403(self):
        """POST with mismatched CSRF tokens raises 403."""
        request = _make_request("POST", session_token="correct-token", header_token="wrong-token")
        with pytest.raises(HTTPException) as exc_info:
            self._fn(request)
        assert exc_info.value.status_code == 403
        assert "mismatch" in exc_info.value.detail

    def test_post_matching_token_passes(self):
        """POST with matching CSRF tokens passes without exception."""
        token = "valid-csrf-token-abc123"
        request = _make_request("POST", session_token=token, header_token=token)
        # Should not raise
        self._fn(request)

    def test_put_matching_token_passes(self):
        """PUT with matching CSRF tokens passes."""
        token = "valid-csrf-token-xyz"
        request = _make_request("PUT", session_token=token, header_token=token)
        self._fn(request)

    def test_delete_matching_token_passes(self):
        """DELETE with matching CSRF tokens passes."""
        token = "valid-csrf-token-del"
        request = _make_request("DELETE", session_token=token, header_token=token)
        self._fn(request)

    def test_patch_mismatched_token_raises_403(self):
        """PATCH with mismatched tokens raises 403."""
        request = _make_request("PATCH", session_token="aaa", header_token="bbb")
        with pytest.raises(HTTPException) as exc_info:
            self._fn(request)
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Integration test: get_current_user_api with session cookie + CSRF check
# ---------------------------------------------------------------------------


class TestGetCurrentUserApiCsrfIntegration:
    """Integration tests for the session-cookie branch of get_current_user_api."""

    def _make_app(self, mock_user):
        """Build a minimal FastAPI app with the real get_current_user_api dependency."""
        # Import AFTER conftest has added app/ to sys.path
        from api_dependencies import get_current_user_api
        from dependencies import get_tenant_id_from_request
        from fastapi import Depends, FastAPI
        from starlette.middleware.sessions import SessionMiddleware

        app = FastAPI()
        app.add_middleware(SessionMiddleware, secret_key="test-secret-key")

        # Override tenant resolution so the dependency doesn't need a real DB hostname
        tenant_id = mock_user["tenant_id"]
        app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

        @app.post("/api/v1/test-endpoint")
        def test_endpoint(user: dict = Depends(get_current_user_api)):
            return {"user_id": str(user["id"])}

        return app

    def _user(self):
        return {
            "id": "00000000-0000-0000-0000-000000000001",
            "tenant_id": "00000000-0000-0000-0000-000000000099",
            "role": "admin",
        }

    def test_post_via_session_cookie_without_csrf_token_returns_403(self):
        """Session-cookie POST with no CSRF header is rejected with 403."""
        from fastapi.testclient import TestClient

        user = self._user()
        app = self._make_app(user)

        with (
            patch("utils.auth.get_current_user", return_value=user),
            patch(
                "database.user_emails.get_primary_email",
                return_value={"email": "admin@example.com"},
            ),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/test-endpoint",
                # No Authorization header → session-cookie path
                # No X-CSRF-Token header
            )

        assert resp.status_code == 403
        assert resp.json()["detail"] in ("CSRF token required", "CSRF token mismatch")

    def test_post_via_bearer_token_does_not_require_csrf(self):
        """Bearer-token POST bypasses CSRF check entirely."""
        from fastapi.testclient import TestClient

        user = self._user()
        app = self._make_app(user)

        token_data = {"user_id": user["id"], "client_id": "00000000-0000-0000-0000-000000000010"}
        client_data = {
            "client_id": "test-client",
            "name": "Test",
            "client_type": "b2b",
        }

        with (
            patch("database.oauth2.validate_token", return_value=token_data),
            patch("database.users.get_user_by_id", return_value=user),
            patch("database.oauth2.get_client_by_id", return_value=client_data),
            patch(
                "database.user_emails.get_primary_email",
                return_value={"email": "admin@example.com"},
            ),
        ):
            client = TestClient(app)
            resp = client.post(
                "/api/v1/test-endpoint",
                headers={"Authorization": "Bearer fake-token"},
                # No X-CSRF-Token header — should not matter for Bearer auth
            )

        assert resp.status_code == 200
