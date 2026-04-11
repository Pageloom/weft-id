"""Tests for routers/auth/_helpers.py - auth routing after email verification."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

# =============================================================================
# _route_after_email_verification Tests
# =============================================================================


def _call_route_after_email_verification(tenant_id, email, route_type, **kwargs):
    """Helper to invoke _route_after_email_verification with a mocked result."""
    from routers.auth._helpers import _route_after_email_verification

    mock_result = MagicMock()
    mock_result.route_type = route_type
    mock_result.idp_id = kwargs.get("idp_id")
    mock_result.user_id = kwargs.get("user_id")

    mock_request = MagicMock()

    with patch("routers.auth._helpers.saml_service.determine_auth_route", return_value=mock_result):
        return _route_after_email_verification(mock_request, tenant_id, email)


def test_route_password():
    """Password route type redirects to login with password form."""
    response = _call_route_after_email_verification(str(uuid4()), "user@example.com", "password")
    assert response.status_code == 303
    assert "/login?" in response.headers["location"]
    assert "show_password=true" in response.headers["location"]
    assert "prefill_email=user%40example.com" in response.headers["location"]


def test_route_idp():
    """IdP route type redirects to SAML login."""
    idp_id = str(uuid4())
    response = _call_route_after_email_verification(
        str(uuid4()), "user@example.com", "idp", idp_id=idp_id
    )
    assert response.status_code == 303
    assert f"/saml/login/{idp_id}" == response.headers["location"]


def test_route_idp_jit():
    """IdP JIT route type also redirects to SAML login."""
    idp_id = str(uuid4())
    response = _call_route_after_email_verification(
        str(uuid4()), "user@example.com", "idp_jit", idp_id=idp_id
    )
    assert response.status_code == 303
    assert f"/saml/login/{idp_id}" == response.headers["location"]


def test_route_inactivated_super_admin():
    """Inactivated super_admin sees inactivation error (same as regular users)."""
    response = _call_route_after_email_verification(
        str(uuid4()),
        "admin@example.com",
        "inactivated",
        user_id=str(uuid4()),
    )
    assert response.status_code == 303
    assert "error=account_inactivated" in response.headers["location"]


def test_route_inactivated_regular_user():
    """Inactivated regular user sees inactivation error."""
    response = _call_route_after_email_verification(
        str(uuid4()),
        "user@example.com",
        "inactivated",
        user_id=str(uuid4()),
    )
    assert response.status_code == 303
    assert "error=account_inactivated" in response.headers["location"]


def test_route_inactivated_no_user_id():
    """Inactivated route without user_id shows inactivation error."""
    response = _call_route_after_email_verification(
        str(uuid4()), "user@example.com", "inactivated", user_id=None
    )
    assert response.status_code == 303
    assert "error=account_inactivated" in response.headers["location"]


def test_route_not_found():
    """Not found route type shows user not found error."""
    response = _call_route_after_email_verification(str(uuid4()), "user@example.com", "not_found")
    assert response.status_code == 303
    assert "error=user_not_found" in response.headers["location"]


def test_route_idp_disabled():
    """IdP disabled route type shows idp disabled error."""
    response = _call_route_after_email_verification(
        str(uuid4()), "user@example.com", "idp_disabled"
    )
    assert response.status_code == 303
    assert "error=idp_disabled" in response.headers["location"]


def test_route_no_auth_method():
    """No auth method route type shows appropriate error."""
    response = _call_route_after_email_verification(
        str(uuid4()), "user@example.com", "no_auth_method"
    )
    assert response.status_code == 303
    assert "error=no_auth_method" in response.headers["location"]


def test_route_invalid_email():
    """Invalid email route type shows invalid email error."""
    response = _call_route_after_email_verification(
        str(uuid4()), "bad@example.com", "invalid_email"
    )
    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_route_unknown_fallback():
    """Unknown route type falls back to password form."""
    response = _call_route_after_email_verification(
        str(uuid4()), "user@example.com", "something_unexpected"
    )
    assert response.status_code == 303
    assert "show_password=true" in response.headers["location"]


def test_route_inactivated_user_not_found_in_db():
    """Inactivated route where user lookup returns None shows inactivation error."""
    response = _call_route_after_email_verification(
        str(uuid4()),
        "user@example.com",
        "inactivated",
        user_id=str(uuid4()),
    )
    assert response.status_code == 303
    assert "error=account_inactivated" in response.headers["location"]
