"""Tests for the user listing route filter parsing and template context."""

from unittest.mock import patch

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app


def _mock_listing_deps(mocker):
    """Patch all service calls made by the listing route."""
    mocker.patch("routers.users.listing.users_service.check_collation_exists", return_value=False)
    mocker.patch("routers.users.listing.users_service.count_users", return_value=0)
    mocker.patch("routers.users.listing.users_service.list_users_raw", return_value=[])
    mocker.patch("routers.users.listing.users_service.get_auth_method_options", return_value=[])
    mocker.patch("routers.users.listing.users_service.get_domain_filter_options", return_value=[])
    mocker.patch("routers.users.listing.users_service.get_group_filter_options", return_value=[])


def _get_context(mock_template):
    """Extract the template context dict from a mocked TemplateResponse."""
    args = mock_template.call_args.args
    return args[2] if len(args) > 2 else mock_template.call_args.kwargs.get("context", {})


class TestNegationFilters:
    """Test that negation prefix '!' is parsed correctly for all filter types."""

    def test_role_negation(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?role=!admin")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["role_negate"] is True
        assert ctx["roles"] == ["admin"]

    def test_status_negation(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?status=!active")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["status_negate"] is True
        assert ctx["statuses"] == ["active"]

    def test_auth_method_negation(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?auth_method=!password_email")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["auth_method_negate"] is True
        assert ctx["auth_methods"] == ["password_email"]

    def test_domain_negation(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?domain=!example.com")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["domain_negate"] is True
        assert ctx["domain"] == "example.com"

    def test_group_negation(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?group_id=!some-group-id")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["group_negate"] is True
        assert ctx["group_id"] == "some-group-id"


class TestSecondaryEmailFilter:
    """Test secondary email filter parsing."""

    def test_secondary_email_yes(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?has_secondary_email=yes")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["has_secondary_email"] is True

    def test_secondary_email_no(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?has_secondary_email=no")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["has_secondary_email"] is False

    def test_secondary_email_domain(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?has_secondary_email=domain:example.com")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["has_secondary_email"] == "domain:example.com"


class TestActivityDateFilter:
    """Test activity date range filter parsing."""

    def test_valid_dates(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?activity_start=2026-01-01&activity_end=2026-03-31")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["activity_start"] == "2026-01-01"
        assert ctx["activity_end"] == "2026-03-31"

    def test_invalid_dates_ignored(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get("/users/list?activity_start=bad&activity_end=bad")

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        assert ctx["activity_start"] == ""
        assert ctx["activity_end"] == ""


class TestFilterCriteriaBuilding:
    """Test that filter_criteria dict is correctly built for template context."""

    def test_negated_filters_in_criteria(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            response = client.get(
                "/users/list?role=!admin&domain=!example.com&group_id=!g1&group_children=0"
            )

        assert response.status_code == 200
        ctx = _get_context(mock_t)
        fc = ctx["filter_criteria"]
        assert fc["roles"] == "!admin"
        assert fc["domain"] == "!example.com"
        assert fc["group_id"] == "!g1"
        assert fc["group_children"] == "0"

    def test_secondary_email_in_criteria(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            client.get("/users/list?has_secondary_email=yes")

        ctx = _get_context(mock_t)
        assert ctx["filter_criteria"]["has_secondary_email"] == "yes"

    def test_activity_dates_in_criteria(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            client.get("/users/list?activity_start=2026-01-01&activity_end=2026-03-31")

        ctx = _get_context(mock_t)
        assert ctx["filter_criteria"]["activity_start"] == "2026-01-01"
        assert ctx["filter_criteria"]["activity_end"] == "2026-03-31"

    def test_empty_negation_resets(self, test_admin_user, override_auth, mocker):
        """When role param is '!' with no value after, negation is reset."""
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            # "!invalid" has no valid roles after stripping the !, so roles stays None
            client.get("/users/list?role=!invalid")

        ctx = _get_context(mock_t)
        assert ctx["roles"] == []
        assert ctx["role_negate"] is False


class TestGroupChildrenFlag:
    """Test group_children=0 flag."""

    def test_group_children_disabled(self, test_admin_user, override_auth, mocker):
        override_auth(test_admin_user, level="admin")
        _mock_listing_deps(mocker)

        with patch("routers.users.listing.templates.TemplateResponse") as mock_t:
            mock_t.return_value = HTMLResponse(content="<html></html>")

            client = TestClient(app)
            client.get("/users/list?group_id=g1&group_children=0")

        ctx = _get_context(mock_t)
        assert ctx["group_include_children"] is False
