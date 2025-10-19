"""Tests for pages.py module."""

from pages import (
    PAGES,
    PagePermission,
    get_all_pages,
    get_first_accessible_child,
    get_nav_items,
    get_navigation_context,
    get_page_by_path,
    has_page_access,
    has_permission,
)


def test_get_page_by_path_found():
    """Test finding a page by path."""
    page = get_page_by_path("/dashboard")
    assert page is not None
    assert page.path == "/dashboard"
    assert page.title == "Dashboard"


def test_get_page_by_path_nested():
    """Test finding a nested page by path."""
    page = get_page_by_path("/account/profile")
    assert page is not None
    assert page.path == "/account/profile"
    assert page.title == "Profile"


def test_get_page_by_path_not_found():
    """Test getting None for non-existent path."""
    page = get_page_by_path("/does-not-exist")
    assert page is None


def test_get_all_pages():
    """Test getting all pages including nested."""
    all_pages = get_all_pages(PAGES)
    paths = [p.path for p in all_pages]

    # Check that both top-level and nested pages are included
    assert "/dashboard" in paths
    assert "/account" in paths
    assert "/account/profile" in paths
    assert "/account/emails" in paths
    assert "/settings/tenant-security" in paths


def test_has_permission_public():
    """Test public pages are accessible to everyone."""
    login_page = get_page_by_path("/login")
    assert has_permission(login_page, None)
    assert has_permission(login_page, "member")
    assert has_permission(login_page, "admin")
    assert has_permission(login_page, "super_admin")


def test_has_permission_authenticated():
    """Test authenticated pages require login."""
    dashboard_page = get_page_by_path("/dashboard")
    assert not has_permission(dashboard_page, None)
    assert has_permission(dashboard_page, "member")
    assert has_permission(dashboard_page, "admin")
    assert has_permission(dashboard_page, "super_admin")


def test_has_permission_admin():
    """Test admin pages require admin or super_admin role."""
    settings_page = get_page_by_path("/settings/privileged-domains")
    assert not has_permission(settings_page, None)
    assert not has_permission(settings_page, "member")
    assert has_permission(settings_page, "admin")
    assert has_permission(settings_page, "super_admin")


def test_has_permission_super_admin():
    """Test super_admin pages require super_admin role."""
    security_page = get_page_by_path("/settings/tenant-security")
    assert not has_permission(security_page, None)
    assert not has_permission(security_page, "member")
    assert not has_permission(security_page, "admin")
    assert has_permission(security_page, "super_admin")


def test_has_page_access_dashboard():
    """Test page access check for dashboard."""
    assert not has_page_access("/dashboard", None)
    assert has_page_access("/dashboard", "member")
    assert has_page_access("/dashboard", "admin")
    assert has_page_access("/dashboard", "super_admin")


def test_has_page_access_admin_page():
    """Test page access check for admin pages."""
    assert not has_page_access("/settings/privileged-domains", None)
    assert not has_page_access("/settings/privileged-domains", "member")
    assert has_page_access("/settings/privileged-domains", "admin")
    assert has_page_access("/settings/privileged-domains", "super_admin")


def test_has_page_access_super_admin_page():
    """Test page access check for super_admin pages."""
    assert not has_page_access("/settings/tenant-security", None)
    assert not has_page_access("/settings/tenant-security", "member")
    assert not has_page_access("/settings/tenant-security", "admin")
    assert has_page_access("/settings/tenant-security", "super_admin")


def test_has_page_access_undefined_page():
    """Test page access denies access to undefined pages."""
    assert not has_page_access("/undefined-page", None)
    assert not has_page_access("/undefined-page", "member")
    assert not has_page_access("/undefined-page", "admin")
    assert not has_page_access("/undefined-page", "super_admin")


def test_get_nav_items_unauthenticated():
    """Test navigation items for unauthenticated users."""
    nav_items = get_nav_items(None)

    # Should only see public pages that are shown in nav
    paths = [item.path for item in nav_items]
    assert "/dashboard" not in paths
    assert "/account" not in paths


def test_get_nav_items_member():
    """Test navigation items for regular member."""
    nav_items = get_nav_items("member")

    paths = [item.path for item in nav_items]
    assert "/dashboard" in paths
    assert "/users" in paths
    assert "/settings" not in paths  # Admin only


def test_get_nav_items_admin():
    """Test navigation items for admin."""
    nav_items = get_nav_items("admin")

    paths = [item.path for item in nav_items]
    assert "/dashboard" in paths
    assert "/users" in paths
    assert "/settings" in paths  # Admin can see settings


def test_get_nav_items_super_admin():
    """Test navigation items for super_admin."""
    nav_items = get_nav_items("super_admin")

    paths = [item.path for item in nav_items]
    assert "/dashboard" in paths
    assert "/users" in paths
    assert "/settings" in paths


def test_get_first_accessible_child_account_member():
    """Test getting first accessible child for account."""
    first_child = get_first_accessible_child("/account", "member")
    assert first_child == "/account/profile"


def test_get_first_accessible_child_users_member():
    """Test getting first accessible child for users."""
    first_child = get_first_accessible_child("/users", "member")
    assert first_child == "/users/list"


def test_get_first_accessible_child_settings_admin():
    """Test getting first accessible child for settings as admin."""
    first_child = get_first_accessible_child("/settings", "admin")
    # Admin can see privileged-domains but not tenant-security
    assert first_child == "/settings/privileged-domains"


def test_get_first_accessible_child_settings_super_admin():
    """Test getting first accessible child for settings as super_admin."""
    first_child = get_first_accessible_child("/settings", "super_admin")
    # Super admin sees tenant-security first (it's listed first in children)
    assert first_child == "/settings/tenant-security"


def test_get_first_accessible_child_no_permission():
    """Test getting None when user has no permission to any children."""
    first_child = get_first_accessible_child("/settings", "member")
    assert first_child is None


def test_get_first_accessible_child_no_children():
    """Test getting None for page without children."""
    first_child = get_first_accessible_child("/dashboard", "member")
    assert first_child is None


def test_get_navigation_context_dashboard():
    """Test navigation context for dashboard page."""
    context = get_navigation_context("/dashboard", "member")

    assert context["current_page"] is not None
    assert context["current_page"].path == "/dashboard"
    assert context["active_top_level"] is not None
    assert context["active_top_level"].path == "/dashboard"
    assert len(context["nav_chain"]) == 1
    assert len(context["sub_nav_items"]) == 0


def test_get_navigation_context_nested_page():
    """Test navigation context for nested page."""
    context = get_navigation_context("/account/profile", "member")

    assert context["current_page"] is not None
    assert context["current_page"].path == "/account/profile"
    assert context["active_top_level"] is not None
    assert context["active_top_level"].path == "/account"
    assert len(context["nav_chain"]) == 2
    assert context["active_sub_level"] is not None
    assert context["active_sub_level"].path == "/account/profile"


def test_get_navigation_context_three_level_page():
    """Test navigation context for three-level nested page."""
    context = get_navigation_context("/account/mfa/setup/totp", "member")

    assert context["current_page"] is not None
    # The setup/totp page doesn't create nav level, so current should be /account/mfa
    assert context["active_top_level"] is not None
    assert context["active_top_level"].path == "/account"


def test_get_navigation_context_sub_nav_items():
    """Test navigation context includes sub-navigation items."""
    context = get_navigation_context("/account/profile", "member")

    sub_nav_paths = [item.path for item in context["sub_nav_items"]]
    assert "/account/profile" in sub_nav_paths
    assert "/account/emails" in sub_nav_paths
    assert "/account/mfa" in sub_nav_paths


def test_get_navigation_context_filters_by_permission():
    """Test navigation context filters items by user permission."""
    # Member should not see admin-only sub-items
    context_member = get_navigation_context("/users/list", "member")
    sub_nav_paths_member = [item.path for item in context_member["sub_nav_items"]]

    # Admin should see admin sub-items
    context_admin = get_navigation_context("/users/list", "admin")
    sub_nav_paths_admin = [item.path for item in context_admin["sub_nav_items"]]

    # Both should see /users/list
    assert "/users/list" in sub_nav_paths_member
    assert "/users/list" in sub_nav_paths_admin


def test_get_navigation_context_top_level_items():
    """Test navigation context includes top-level nav items."""
    context = get_navigation_context("/dashboard", "admin")

    top_level_paths = [item.path for item in context["top_level_items"]]
    assert "/dashboard" in top_level_paths
    assert "/users" in top_level_paths
    assert "/settings" in top_level_paths


def test_get_navigation_context_unknown_path():
    """Test navigation context for unknown path."""
    context = get_navigation_context("/unknown-path", "member")

    assert context["current_page"] is None
    assert len(context["nav_chain"]) == 0
    assert context["active_top_level"] is None


def test_page_get_all_paths():
    """Test Page.get_all_paths() method."""
    account_page = get_page_by_path("/account")
    all_paths = account_page.get_all_paths()

    assert "/account" in all_paths
    assert "/account/profile" in all_paths
    assert "/account/emails" in all_paths
    assert "/account/mfa" in all_paths
    assert "/account/mfa/setup/totp" in all_paths


def test_page_without_children_get_all_paths():
    """Test get_all_paths for page without children."""
    dashboard_page = get_page_by_path("/dashboard")
    all_paths = dashboard_page.get_all_paths()

    assert all_paths == ["/dashboard"]


def test_page_permission_enum():
    """Test PagePermission enum values."""
    assert PagePermission.PUBLIC == "public"
    assert PagePermission.AUTHENTICATED == "authenticated"
    assert PagePermission.ADMIN == "admin"
    assert PagePermission.SUPER_ADMIN == "super_admin"


def test_pages_structure_login():
    """Test login page configuration."""
    login_page = get_page_by_path("/login")
    assert login_page is not None
    assert login_page.permission == PagePermission.PUBLIC
    assert login_page.show_in_nav is False
    assert login_page.creates_nav_level is False


def test_pages_structure_account():
    """Test account page configuration."""
    account_page = get_page_by_path("/account")
    assert account_page is not None
    assert account_page.permission == PagePermission.AUTHENTICATED
    assert account_page.icon == "user"
    assert account_page.children is not None
    assert len(account_page.children) == 3  # profile, emails, mfa


def test_pages_structure_mfa_workflow():
    """Test MFA workflow pages configuration."""
    mfa_verify_page = get_page_by_path("/mfa/verify")
    assert mfa_verify_page is not None
    assert mfa_verify_page.permission == PagePermission.PUBLIC
    assert mfa_verify_page.show_in_nav is False


def test_has_permission_hierarchy():
    """Test that permission hierarchy works correctly."""
    # A super_admin user should have access to all permission levels
    public_page = get_page_by_path("/login")
    auth_page = get_page_by_path("/dashboard")
    admin_page = get_page_by_path("/settings/privileged-domains")
    super_admin_page = get_page_by_path("/settings/tenant-security")

    # Super admin can access everything
    assert has_permission(public_page, "super_admin")
    assert has_permission(auth_page, "super_admin")
    assert has_permission(admin_page, "super_admin")
    assert has_permission(super_admin_page, "super_admin")

    # Admin can access public, authenticated, and admin
    assert has_permission(public_page, "admin")
    assert has_permission(auth_page, "admin")
    assert has_permission(admin_page, "admin")
    assert not has_permission(super_admin_page, "admin")

    # Member can access public and authenticated
    assert has_permission(public_page, "member")
    assert has_permission(auth_page, "member")
    assert not has_permission(admin_page, "member")
    assert not has_permission(super_admin_page, "member")


def test_settings_children_permissions():
    """Test that settings children have appropriate permissions."""
    settings_page = get_page_by_path("/settings")
    assert settings_page is not None

    # Find tenant-security (super_admin only)
    tenant_security = get_page_by_path("/settings/tenant-security")
    assert tenant_security is not None
    assert tenant_security.permission == PagePermission.SUPER_ADMIN

    # Find privileged-domains (admin)
    privileged_domains = get_page_by_path("/settings/privileged-domains")
    assert privileged_domains is not None
    assert privileged_domains.permission == PagePermission.ADMIN


def test_users_page_has_children():
    """Test users page has expected children."""
    users_page = get_page_by_path("/users")
    assert users_page is not None
    assert users_page.children is not None

    child_paths = [child.path for child in users_page.children]
    assert "/users/list" in child_paths
    assert "/users/user" in child_paths


def test_users_user_detail_not_in_nav():
    """Test user detail page is not shown in navigation."""
    user_detail = get_page_by_path("/users/user")
    assert user_detail is not None
    assert user_detail.show_in_nav is False
    assert user_detail.creates_nav_level is False
