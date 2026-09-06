"""Tests for utils.template_context module."""

from unittest.mock import Mock, patch


def test_get_template_context_with_authenticated_user(test_user):
    """Test getting template context with an authenticated user."""
    from utils.template_context import get_template_context

    # Create mock request
    request = Mock()
    request.url.path = "/dashboard"
    request.session = {"user_id": test_user["id"]}

    with patch("utils.template_context.get_navigation_context") as mock_nav:
        mock_nav.return_value = {
            "top_level_items": [{"label": "Dashboard", "url": "/dashboard"}],
            "secondary_items": [],
        }

        context = get_template_context(request, test_user["tenant_id"], custom_key="custom_value")

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

    with patch("utils.template_context.get_navigation_context") as mock_nav:
        context = get_template_context(request, "any-tenant-id")

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
    import database
    from utils.template_context import get_template_context

    # Update user's timezone and locale
    database.users.update_user_timezone_and_locale(
        test_user["tenant_id"], test_user["id"], "America/New_York", "en_US"
    )

    # Create mock request
    request = Mock()
    request.url.path = "/profile"
    request.session = {"user_id": test_user["id"]}

    with patch("utils.template_context.get_navigation_context") as mock_nav:
        with patch("utils.template_context.create_datetime_formatter") as mock_fmt:
            mock_nav.return_value = {"top_level_items": []}
            mock_fmt.return_value = lambda x: "formatted"

            get_template_context(request, test_user["tenant_id"])

            # Verify datetime formatter was created with user's timezone and locale
            mock_fmt.assert_called_once_with("America/New_York", "en_US")


def test_get_template_context_with_user_locale(test_user):
    """Test that template context uses user's locale for datetime formatter."""
    import database
    from utils.template_context import get_template_context

    # Update user's locale
    database.users.update_user_locale(test_user["tenant_id"], test_user["id"], "fr-FR")

    # Create mock request
    request = Mock()
    request.url.path = "/settings"
    request.session = {"user_id": test_user["id"]}

    with patch("utils.template_context.get_navigation_context") as mock_nav:
        with patch("utils.template_context.create_datetime_formatter") as mock_fmt:
            mock_nav.return_value = {"top_level_items": []}
            mock_fmt.return_value = lambda x: "formatted"

            get_template_context(request, test_user["tenant_id"])

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

    with patch("utils.template_context.create_datetime_formatter") as mock_fmt:
        mock_fmt.return_value = lambda x: "formatted"

        get_template_context(request, "any-tenant-id")

        # Verify default locale en_US is used
        mock_fmt.assert_called_once_with(None, "en_US")


def test_get_template_context_backward_compatibility():
    """Test that nav_items is provided for backward compatibility."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/dashboard"
    request.session = {"user_id": "some-user-id"}

    nav_items = [{"label": "Item 1", "url": "/item1"}, {"label": "Item 2", "url": "/item2"}]

    with patch("utils.template_context.get_current_user") as mock_user:
        with patch("utils.template_context.get_navigation_context") as mock_nav:
            mock_user.return_value = {"id": "some-user-id", "role": "member"}
            mock_nav.return_value = {"top_level_items": nav_items, "secondary_items": []}

            context = get_template_context(request, "tenant-id")

            # Both nav_items and nav should be present
            assert context["nav_items"] == nav_items
            assert context["nav"]["top_level_items"] == nav_items


def test_get_template_context_with_admin_user(test_admin_user):
    """Test getting template context with an admin user."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/admin"
    request.session = {"user_id": test_admin_user["id"]}

    with patch("utils.template_context.get_navigation_context") as mock_nav:
        mock_nav.return_value = {"top_level_items": [{"label": "Admin Panel", "url": "/admin"}]}

        context = get_template_context(request, test_admin_user["tenant_id"])

    assert context["user"]["role"] == "admin"
    # Verify navigation was called with admin role
    mock_nav.assert_called_once_with("/admin", "admin")


# =============================================================================
# Requests Nav Badge Count
# =============================================================================


def test_requests_badge_count_zero_for_member(test_user):
    """Member role never triggers the pending-count queries, and gets 0."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            return_value={"active_top_level": Mock(path="/directory")},
        ),
        patch("services.reactivation.count_pending_requests") as mock_reactivation,
        patch("services.users.count_users_with_missing_required") as mock_attributes,
    ):
        context = get_template_context(request, test_user["tenant_id"])

    assert context["nav"]["requests_badge_count"] == 0
    mock_reactivation.assert_not_called()
    mock_attributes.assert_not_called()


def test_requests_badge_count_sums_reactivations_and_attributes_for_admin(test_admin_user):
    """Badge count is the sum of pending reactivations and incomplete profiles."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            return_value={"active_top_level": Mock(path="/directory")},
        ),
        patch("services.reactivation.count_pending_requests", return_value=2) as mock_reactivation,
        patch(
            "services.users.count_users_with_missing_required", return_value=3
        ) as mock_attributes,
    ):
        context = get_template_context(request, test_admin_user["tenant_id"])

    assert context["nav"]["requests_badge_count"] == 5
    mock_reactivation.assert_called_once()
    mock_attributes.assert_called_once()


def test_requests_badge_count_included_for_super_admin(test_super_admin_user):
    """Super admins also see the summed badge count."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_super_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            return_value={"active_top_level": Mock(path="/directory")},
        ),
        patch("services.reactivation.count_pending_requests", return_value=1),
        patch("services.users.count_users_with_missing_required", return_value=0),
    ):
        context = get_template_context(request, test_super_admin_user["tenant_id"])

    assert context["nav"]["requests_badge_count"] == 1


def test_requests_badge_count_swallows_forbidden_error(test_admin_user):
    """A ForbiddenError from either count call degrades to 0, not a 500."""
    from services.exceptions import ForbiddenError
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            return_value={"active_top_level": Mock(path="/directory")},
        ),
        patch(
            "services.reactivation.count_pending_requests",
            side_effect=ForbiddenError(message="Admin required", code="admin_required"),
        ),
        patch("utils.template_context.logger.exception"),
    ):
        context = get_template_context(request, test_admin_user["tenant_id"])

    assert context["nav"]["requests_badge_count"] == 0


def test_requests_badge_count_swallows_generic_service_error(test_admin_user):
    """A non-Forbidden ServiceError from either count call also degrades to 0.

    Widened from `except ForbiddenError` to `except ServiceError` so any other
    service-layer error can't 500 an otherwise-unrelated page render.
    """
    from services.exceptions import ValidationError
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            return_value={"active_top_level": Mock(path="/directory")},
        ),
        patch(
            "services.reactivation.count_pending_requests",
            side_effect=ValidationError(message="Bad input", code="validation_error"),
        ),
        patch("utils.template_context.logger.exception"),
    ):
        context = get_template_context(request, test_admin_user["tenant_id"])

    assert context["nav"]["requests_badge_count"] == 0


def test_requests_badge_count_not_computed_outside_directory_section(test_admin_user):
    """The two count queries are skipped entirely outside the Directory section.

    The badge only ever renders in base.html's Directory sub-nav, so when the
    active top-level section is something else, the count is 0 and neither
    service is queried.
    """
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/security/sessions"
    request.session = {"user_id": test_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            return_value={"active_top_level": Mock(path="/security")},
        ),
        patch("services.reactivation.count_pending_requests") as mock_reactivation,
        patch("services.users.count_users_with_missing_required") as mock_attributes,
    ):
        context = get_template_context(request, test_admin_user["tenant_id"])

    assert context["nav"]["requests_badge_count"] == 0
    mock_reactivation.assert_not_called()
    mock_attributes.assert_not_called()


def test_requests_badge_count_absent_when_no_user():
    """No user in session means no nav context at all, so no badge key."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/login"
    request.session = {}

    context = get_template_context(request, "any-tenant-id")

    assert context["nav"] == {}
    assert "requests_badge_count" not in context["nav"]


def test_requests_badge_count_cached_after_first_compute(test_admin_user):
    """The summed count is cached per tenant; a second render skips the queries."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            side_effect=lambda path, role: {"active_top_level": Mock(path="/directory")},
        ),
        patch("services.reactivation.count_pending_requests", return_value=2) as mock_reactivation,
        patch(
            "services.users.count_users_with_missing_required", return_value=3
        ) as mock_attributes,
    ):
        context1 = get_template_context(request, test_admin_user["tenant_id"])
        context2 = get_template_context(request, test_admin_user["tenant_id"])

    assert context1["nav"]["requests_badge_count"] == 5
    assert context2["nav"]["requests_badge_count"] == 5
    mock_reactivation.assert_called_once()
    mock_attributes.assert_called_once()


def test_requests_badge_count_swallows_non_service_error(test_admin_user):
    """A non-ServiceError (e.g. psycopg OperationalError) degrades to 0, not a 500.

    The error page itself calls get_template_context, so a DB failure in the
    count must not turn the error page into a 500.
    """
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            return_value={"active_top_level": Mock(path="/directory")},
        ),
        patch(
            "services.reactivation.count_pending_requests",
            side_effect=RuntimeError("db down"),
        ),
        patch("utils.template_context.logger.exception"),
    ):
        context = get_template_context(request, test_admin_user["tenant_id"])

    assert context["nav"]["requests_badge_count"] == 0


def test_requests_badge_count_failure_not_cached(test_admin_user):
    """A failed count is not cached, so the next render retries the queries."""
    from utils.template_context import get_template_context

    request = Mock()
    request.url.path = "/directory/requests"
    request.session = {"user_id": test_admin_user["id"]}

    with (
        patch(
            "utils.template_context.get_navigation_context",
            side_effect=lambda path, role: {"active_top_level": Mock(path="/directory")},
        ),
        patch(
            "services.reactivation.count_pending_requests",
            side_effect=[RuntimeError("db down"), 2],
        ) as mock_reactivation,
        patch("services.users.count_users_with_missing_required", return_value=3),
        patch("utils.template_context.logger.exception"),
    ):
        context1 = get_template_context(request, test_admin_user["tenant_id"])
        context2 = get_template_context(request, test_admin_user["tenant_id"])

    assert context1["nav"]["requests_badge_count"] == 0
    assert context2["nav"]["requests_badge_count"] == 5
    assert mock_reactivation.call_count == 2
