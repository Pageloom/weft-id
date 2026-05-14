"""Tests for FastAPI dependencies."""

from unittest.mock import Mock, patch

import pytest
from dependencies import (
    RedirectError,
    get_current_user,
    get_tenant_id_from_request,
    normalize_host,
    require_admin,
    require_current_user,
    require_super_admin,
)
from fastapi import HTTPException


def test_normalize_host_basic():
    """Test normalize_host with basic hostname."""
    assert normalize_host("example.com") == "example.com"


def test_normalize_host_with_port():
    """Test normalize_host removes port number."""
    assert normalize_host("example.com:8000") == "example.com"


def test_normalize_host_with_trailing_dot():
    """Test normalize_host removes trailing dot."""
    assert normalize_host("example.com.") == "example.com"


def test_normalize_host_with_uppercase():
    """Test normalize_host converts to lowercase."""
    assert normalize_host("EXAMPLE.COM") == "example.com"


def test_normalize_host_with_none():
    """Test normalize_host handles None."""
    assert normalize_host(None) == ""


def test_normalize_host_complex():
    """Test normalize_host with complex input."""
    assert normalize_host("EXAMPLE.COM.:8080") == "example.com"


def test_get_tenant_id_from_request_success(test_tenant):
    """Test successful tenant ID extraction from request."""
    request = Mock()

    # Use the actual subdomain from test_tenant with a proper domain
    with patch("settings.BASE_DOMAIN", "example.com"):
        request.headers.get.return_value = f"{test_tenant['subdomain']}.example.com"

        tenant_id = get_tenant_id_from_request(request)

        assert tenant_id == test_tenant["id"]


def test_get_tenant_id_from_request_with_x_forwarded_host(test_tenant):
    """Test tenant ID extraction using x-forwarded-host header."""
    request = Mock()

    with patch("settings.BASE_DOMAIN", "example.com"):

        def get_header(name):
            if name == "x-forwarded-host":
                return f"{test_tenant['subdomain']}.example.com"
            return None

        request.headers.get.side_effect = get_header

        tenant_id = get_tenant_id_from_request(request)

        assert tenant_id == test_tenant["id"]


def test_get_tenant_id_from_request_unknown_host():
    """Test tenant ID extraction with unknown host."""
    request = Mock()
    request.headers.get.return_value = "unknown.badomain.com"

    with patch("settings.BASE_DOMAIN", "example.com"):
        with pytest.raises(HTTPException) as exc_info:
            get_tenant_id_from_request(request)

        assert exc_info.value.status_code == 404
        assert "Unknown host" in exc_info.value.detail


def test_get_tenant_id_from_request_unknown_subdomain():
    """Test tenant ID extraction with unknown subdomain."""
    request = Mock()

    with patch("settings.BASE_DOMAIN", "example.com"):
        request.headers.get.return_value = "nonexistent.example.com"

        with pytest.raises(HTTPException) as exc_info:
            get_tenant_id_from_request(request)

        assert exc_info.value.status_code == 404
        assert "No tenant configured" in exc_info.value.detail


def test_get_current_user_authenticated(test_user):
    """Test get_current_user with authenticated user."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_user

        user = get_current_user(request, test_user["tenant_id"])

        assert user == test_user


def test_get_current_user_not_authenticated():
    """Test get_current_user without authentication."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = None

        user = get_current_user(request, "any-tenant-id")

        assert user is None


def test_require_current_user_authenticated(test_user):
    """Test require_current_user with authenticated user."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_user

        user = require_current_user(request, test_user["tenant_id"])

        assert user == test_user


def test_require_current_user_not_authenticated():
    """Test require_current_user redirects when not authenticated."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = None

        with pytest.raises(RedirectError) as exc_info:
            require_current_user(request, "any-tenant-id")

        assert exc_info.value.status_code == 303
        assert exc_info.value.url == "/login"


def test_require_admin_with_admin_user(test_admin_user):
    """Test require_admin with admin user."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_admin_user

        user = require_admin(request, test_admin_user["tenant_id"])

        assert user == test_admin_user


def test_require_admin_with_super_admin_user(test_super_admin_user):
    """Test require_admin with super_admin user (should also work)."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_super_admin_user

        user = require_admin(request, test_super_admin_user["tenant_id"])

        assert user == test_super_admin_user


def test_require_admin_with_regular_user(test_user):
    """Test require_admin redirects regular user to dashboard."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_user

        with pytest.raises(RedirectError) as exc_info:
            require_admin(request, test_user["tenant_id"])

        assert exc_info.value.status_code == 303
        assert exc_info.value.url == "/dashboard"


def test_require_admin_not_authenticated():
    """Test require_admin redirects to login when not authenticated."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = None

        with pytest.raises(RedirectError) as exc_info:
            require_admin(request, "any-tenant-id")

        assert exc_info.value.status_code == 303
        assert exc_info.value.url == "/login"


def test_require_super_admin_with_super_admin_user(test_super_admin_user):
    """Test require_super_admin with super_admin user."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_super_admin_user

        user = require_super_admin(request, test_super_admin_user["tenant_id"])

        assert user == test_super_admin_user


def test_require_super_admin_with_admin_user(test_admin_user):
    """Test require_super_admin redirects admin user (not super_admin)."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_admin_user

        with pytest.raises(RedirectError) as exc_info:
            require_super_admin(request, test_admin_user["tenant_id"])

        assert exc_info.value.status_code == 303
        assert exc_info.value.url == "/dashboard"


def test_require_super_admin_with_regular_user(test_user):
    """Test require_super_admin redirects regular user."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = test_user

        with pytest.raises(RedirectError) as exc_info:
            require_super_admin(request, test_user["tenant_id"])

        assert exc_info.value.status_code == 303
        assert exc_info.value.url == "/dashboard"


def test_require_super_admin_not_authenticated():
    """Test require_super_admin redirects to login when not authenticated."""
    request = Mock()

    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = None

        with pytest.raises(RedirectError) as exc_info:
            require_super_admin(request, "any-tenant-id")

        assert exc_info.value.status_code == 303
        assert exc_info.value.url == "/login"


# ---------------------------------------------------------------------------
# force_profile_completion gate (Iteration 7)
# ---------------------------------------------------------------------------


def _user_with_force_flag(user, flag=True):
    """Return a shallow copy of ``user`` with ``force_profile_completion`` set."""
    new = dict(user)
    new["force_profile_completion"] = flag
    return new


def test_require_current_user_force_completion_redirects_off_whitelist(test_user):
    """A flagged user hitting any non-whitelisted path is redirected to profile."""
    request = Mock()
    request.url.path = "/dashboard"
    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = _user_with_force_flag(test_user, True)
        with pytest.raises(RedirectError) as exc_info:
            require_current_user(request, test_user["tenant_id"])
    assert exc_info.value.url == "/account/profile"
    assert exc_info.value.status_code == 303


def test_require_current_user_force_completion_allows_profile_page(test_user):
    """The profile page itself stays accessible while the flag is set."""
    request = Mock()
    request.url.path = "/account/profile"
    flagged = _user_with_force_flag(test_user, True)
    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = flagged
        result = require_current_user(request, test_user["tenant_id"])
    assert result == flagged


def test_require_current_user_force_completion_allows_logout(test_user):
    request = Mock()
    request.url.path = "/logout"
    flagged = _user_with_force_flag(test_user, True)
    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = flagged
        result = require_current_user(request, test_user["tenant_id"])
    assert result == flagged


def test_require_current_user_force_completion_allows_profile_submit(test_user):
    """The form-submit endpoint must keep working so the gate can clear."""
    request = Mock()
    request.url.path = "/account/profile/update-attributes"
    flagged = _user_with_force_flag(test_user, True)
    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = flagged
        result = require_current_user(request, test_user["tenant_id"])
    assert result == flagged


def test_require_current_user_force_completion_allows_static_assets(test_user):
    request = Mock()
    request.url.path = "/static/js/utils.js"
    flagged = _user_with_force_flag(test_user, True)
    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = flagged
        result = require_current_user(request, test_user["tenant_id"])
    assert result == flagged


def test_require_admin_force_completion_redirects_admin_routes(test_admin_user):
    """Even admins land on the profile page if their flag is set."""
    request = Mock()
    request.url.path = "/admin/audit/events"
    with patch("dependencies.auth.get_current_user") as mock_auth:
        mock_auth.return_value = _user_with_force_flag(test_admin_user, True)
        with pytest.raises(RedirectError) as exc_info:
            require_admin(request, test_admin_user["tenant_id"])
    assert exc_info.value.url == "/account/profile"
