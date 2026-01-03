"""Tests for routers/mfa.py endpoints - redirect behavior tests.

Note: E2E tests for actual MFA verification are in test_mfa_e2e.py.
These tests verify redirect behavior when there's no pending MFA session.
"""

from fastapi.testclient import TestClient
from main import app


def test_mfa_verify_page_no_pending_session(test_tenant):
    """Test MFA verify page redirects without pending MFA session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.get("/mfa/verify", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_mfa_verify_post_no_pending_session(test_tenant):
    """Test MFA verify POST redirects without pending session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post("/mfa/verify", data={"code": "123456"}, follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_mfa_send_email_code_no_pending_session(test_tenant):
    """Test send email code redirects without pending session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post("/mfa/verify/send-email", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
