"""Tests for utils.template_context module."""

import pytest
from unittest.mock import Mock, patch


def test_get_template_context_with_authenticated_user(test_user):
    """Test getting template context with an authenticated user."""
    from utils.template_context import get_template_context

    # Create mock request
    request = Mock()
    request.url.path = "/dashboard"
    request.session = {
        "user_id": test_user["id"]
    }

    with patch('utils.template_context.get_navigation_context') as mock_nav:
        mock_nav.return_value = {
            "top_level_items": [
                {"label": "Dashboard", "url": "/dashboard"}
            ],
            "secondary_items": []
        }

        context = get_template_context(
            request,
            test_user["tenant_id"],
            custom_key="custom_value"
        )

    assert context is not None
    assert context["request"] == request
    assert context["user"] is not None
    assert context["user"]["id"] == test_user["id"]
    assert "nav_items" in context
    assert "nav" in context
    assert "fmt_datetime" in context
    assert context["custom_key"] == "custom_value"

    # Verify navigation context was called with user role
    mock_nav.assert_called_once_with("/dashboard", test_user["role"])


def test_get_template_context_without_user():
    """Test getting template context without an authenticated user."""
    from utils.template_context import get_template_context

    # Create mock request with no user in session
    request = Mock()
    request.url.path = "/login"
    request.session = {}

    with patch('utils.template_context.get_navigation_context') as mock_nav:
        context = get_template_context(
            request,
            "any-tenant-id"
        )

    assert context is not None
    assert context["request"] == request
    assert context["user"] is None
    assert context["nav_items"] == []
    assert context["nav"] == {}
    assert "fmt_datetime" in context

    # Navigation should not be called when no user
    mock_nav.assert_not_called()


def test_get_template_context_with_user_timezone(test_user):
    """Test that template context uses user's timezone for datetime formatter."""
    from utils.template_context import get_template_context
    import database

    # Update user's timezone and locale
    database.users.update_user_timezone_and_locale(
        test_user["tenant_id"],
        test_user["id"],
        "America/New_York",
        "en_US"
    )

    # Create mock request
    request = Mock()
    request.url.path = "/profile"
    request.session = {
        "user_id": test_user["id"]
    }

    with patch('utils.template_context.get_navigation_context') as mock_nav:
        with patch('utils.template_context.create_datetime_formatter') as mock_fmt:
            mock_nav.return_value = {"top_level_items": []}
            mock_fmt.return_value = lambda x: "formatted"

            context = get_template_context(
                request,
                test_user["tenant_id"]
            )

            # Verify datetime formatter was created with user's timezone and locale
            mock_fmt.assert_called_once_with("America/New_York", "en_US")


def test_get_template_context_with_user_locale(test_user):
    """Test that template context uses user's locale for datetime formatter."""
    from utils.template_context import get_template_context
    import database

    # Update user's locale
    database.users.update_user_locale(
        test_user["tenant_id"],
        test_user["id"],
        "fr-FR"
    )

    # Create mock request
    request = Mock()
    request.url.path = "/settings"
    request.session = {
        "user_id": test_user["id"]
    }

    with patch('utils.template_context.get_navigation_context') as mock_nav:
        with patch('utils.template_context.create_datetime_formatter') as mock_fmt:
            mock_nav.return_value = {"top_level_items": []}
            mock_fmt.return_value = lambda x: "formatted"

            context = get_template_context(
                request,
                test_user["tenant_id"]
            )

            # Verify datetime formatter was created with user's locale
            # Timezone should be None if not set
            mock_fmt.assert_called_once()
            call_args = mock_fmt.call_args[0]
            assert call_args[1] == "fr-FR"


def test_get_template_context_default_locale_for_no_user():
    """Test that default locale is used when no user is authenticated."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/"
    request.session = {}

    with patch('utils.template_context.create_datetime_formatter') as mock_fmt:
        mock_fmt.return_value = lambda x: "formatted"

        context = get_template_context(
            request,
            "any-tenant-id"
        )

        # Verify default locale en_US is used
        mock_fmt.assert_called_once_with(None, "en_US")


def test_get_template_context_backward_compatibility():
    """Test that nav_items is provided for backward compatibility."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/dashboard"
    request.session = {"user_id": "some-user-id"}

    nav_items = [
        {"label": "Item 1", "url": "/item1"},
        {"label": "Item 2", "url": "/item2"}
    ]

    with patch('utils.template_context.get_current_user') as mock_user:
        with patch('utils.template_context.get_navigation_context') as mock_nav:
            mock_user.return_value = {"id": "some-user-id", "role": "member"}
            mock_nav.return_value = {
                "top_level_items": nav_items,
                "secondary_items": []
            }

            context = get_template_context(
                request,
                "tenant-id"
            )

            # Both nav_items and nav should be present
            assert context["nav_items"] == nav_items
            assert context["nav"]["top_level_items"] == nav_items


def test_get_template_context_with_admin_user(test_admin_user):
    """Test getting template context with an admin user."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/admin"
    request.session = {
        "user_id": test_admin_user["id"]
    }

    with patch('utils.template_context.get_navigation_context') as mock_nav:
        mock_nav.return_value = {
            "top_level_items": [
                {"label": "Admin Panel", "url": "/admin"}
            ]
        }

        context = get_template_context(
            request,
            test_admin_user["tenant_id"]
        )

    assert context["user"]["role"] == "admin"
    # Verify navigation was called with admin role
    mock_nav.assert_called_once_with("/admin", "admin")
