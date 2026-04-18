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
    assert "/admin/settings/security" in paths


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
    settings_page = get_page_by_path("/admin/settings/privileged-domains")
    assert not has_permission(settings_page, None)
    assert not has_permission(settings_page, "member")
    assert has_permission(settings_page, "admin")
    assert has_permission(settings_page, "super_admin")


def test_has_permission_super_admin():
    """Test super_admin pages require super_admin role."""
    security_page = get_page_by_path("/admin/settings/security")
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
    assert not has_page_access("/admin/settings/privileged-domains", None)
    assert not has_page_access("/admin/settings/privileged-domains", "member")
    assert has_page_access("/admin/settings/privileged-domains", "admin")
    assert has_page_access("/admin/settings/privileged-domains", "super_admin")


def test_has_page_access_super_admin_page():
    """Test page access check for super_admin pages."""
    assert not has_page_access("/admin/settings/security", None)
    assert not has_page_access("/admin/settings/security", "member")
    assert not has_page_access("/admin/settings/security", "admin")
    assert has_page_access("/admin/settings/security", "super_admin")


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
    assert "/admin" not in paths  # Admin only


def test_get_nav_items_admin():
    """Test navigation items for admin."""
    nav_items = get_nav_items("admin")

    paths = [item.path for item in nav_items]
    assert "/dashboard" in paths
    assert "/users" in paths
    assert "/admin" in paths  # Admin can see admin menu


def test_get_nav_items_super_admin():
    """Test navigation items for super_admin."""
    nav_items = get_nav_items("super_admin")

    paths = [item.path for item in nav_items]
    assert "/dashboard" in paths
    assert "/users" in paths
    assert "/admin" in paths


def test_get_first_accessible_child_account_member():
    """Test getting first accessible child for account."""
    first_child = get_first_accessible_child("/account", "member")
    assert first_child == "/account/profile"


def test_get_first_accessible_child_users_member():
    """Test getting first accessible child for users."""
    first_child = get_first_accessible_child("/users", "member")
    assert first_child == "/users/list"


def test_get_first_accessible_child_settings_admin():
    """Test getting first accessible child for admin menu as admin."""
    first_child = get_first_accessible_child("/admin", "admin")
    # Admin can see security or privileged-domains (security is first but requires super_admin)
    assert first_child == "/admin/settings/privileged-domains"


def test_get_first_accessible_child_settings_super_admin():
    """Test getting first accessible child for admin menu as super_admin."""
    first_child = get_first_accessible_child("/admin", "super_admin")
    # Super admin sees security first, which recurses to sessions tab
    assert first_child == "/admin/settings/security/sessions"


def test_get_first_accessible_child_no_permission():
    """Test getting None when user has no permission to any children."""
    first_child = get_first_accessible_child("/admin", "member")
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
    assert "/admin" in top_level_paths


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
    # profile, password, emails, mfa, passkeys, background-jobs
    assert len(account_page.children) == 6


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
    admin_page = get_page_by_path("/admin/settings/privileged-domains")
    super_admin_page = get_page_by_path("/admin/settings/security")

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
    """Test that admin page children have appropriate permissions."""
    admin_page = get_page_by_path("/admin")
    assert admin_page is not None

    # Find security (super_admin only)
    admin_security = get_page_by_path("/admin/settings/security")
    assert admin_security is not None
    assert admin_security.permission == PagePermission.SUPER_ADMIN

    # Find privileged-domains (admin)
    privileged_domains = get_page_by_path("/admin/settings/privileged-domains")
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


# =============================================================================
# Integration Pages Tests
# =============================================================================


def test_integrations_page_exists():
    """Test that the integrations page is registered."""
    page = get_page_by_path("/admin/integrations")
    assert page is not None
    assert page.title == "Integrations"
    assert page.permission == PagePermission.ADMIN
    assert page.show_in_nav is True


def test_integrations_apps_page_exists():
    """Test that the integrations apps page is registered."""
    page = get_page_by_path("/admin/integrations/apps")
    assert page is not None
    assert page.title == "Apps"
    assert page.permission == PagePermission.ADMIN
    assert page.show_in_nav is True


def test_integrations_b2b_page_exists():
    """Test that the integrations B2B page is registered."""
    page = get_page_by_path("/admin/integrations/b2b")
    assert page is not None
    assert page.title == "B2B"
    assert page.permission == PagePermission.SUPER_ADMIN
    assert page.show_in_nav is True


def test_integrations_page_access_member():
    """Test that members cannot access integration pages."""
    assert not has_page_access("/admin/integrations", "member")
    assert not has_page_access("/admin/integrations/apps", "member")
    assert not has_page_access("/admin/integrations/b2b", "member")


def test_integrations_page_access_admin():
    """Test that admins can access integration pages (except B2B)."""
    assert has_page_access("/admin/integrations", "admin")
    assert has_page_access("/admin/integrations/apps", "admin")
    assert not has_page_access("/admin/integrations/b2b", "admin")


def test_integrations_page_access_super_admin():
    """Test that super_admins can access integration pages."""
    assert has_page_access("/admin/integrations", "super_admin")
    assert has_page_access("/admin/integrations/apps", "super_admin")
    assert has_page_access("/admin/integrations/b2b", "super_admin")


def test_integrations_first_accessible_child_admin():
    """Test that first accessible child for integrations is apps."""
    first_child = get_first_accessible_child("/admin/integrations", "admin")
    assert first_child == "/admin/integrations/apps"


def test_integrations_children_structure():
    """Test the integrations page has expected children."""
    page = get_page_by_path("/admin/integrations")
    assert page.children is not None
    assert len(page.children) == 2

    child_paths = [child.path for child in page.children]
    assert "/admin/integrations/apps" in child_paths
    assert "/admin/integrations/b2b" in child_paths


def test_service_providers_in_settings():
    """Test that service providers is under settings, next to identity providers."""
    page = get_page_by_path("/admin/settings")
    assert page.children is not None

    child_paths = [child.path for child in page.children]
    assert "/admin/settings/identity-providers" in child_paths
    assert "/admin/settings/service-providers" in child_paths


def test_integrations_in_admin_nav():
    """Test that integrations appears in admin navigation."""
    admin_page = get_page_by_path("/admin")
    assert admin_page is not None

    child_titles = [child.title for child in admin_page.children]
    assert "Integrations" in child_titles


def test_integrations_get_all_paths():
    """Test get_all_paths includes integrations pages."""
    page = get_page_by_path("/admin/integrations")
    all_paths = page.get_all_paths()

    assert "/admin/integrations" in all_paths
    assert "/admin/integrations/apps" in all_paths
    assert "/admin/integrations/b2b" in all_paths


# =============================================================================
# Documentation Links Tests
# =============================================================================


def test_docs_path_defaults_to_none():
    """Test that docs_path defaults to None for pages without it."""
    login_page = get_page_by_path("/login")
    assert login_page.docs_path is None


def test_docs_path_set_on_dashboard():
    """Test that dashboard has a docs_path."""
    page = get_page_by_path("/dashboard")
    assert page.docs_path == "/docs/user-guide/dashboard/"


def test_docs_path_set_on_admin_pages():
    """Test that key admin pages have docs_path values."""
    sec = "/admin/settings/security"
    idp = "/docs/admin-guide/identity-providers"
    cases = {
        sec: "/docs/admin-guide/security/",
        f"{sec}/sessions": "/docs/admin-guide/security/sessions/",
        f"{sec}/certificates": "/docs/admin-guide/security/certificates/",
        f"{sec}/permissions": "/docs/admin-guide/security/permissions/",
        "/admin/settings/privileged-domains": f"{idp}/privileged-domains/",
        "/admin/settings/identity-providers": f"{idp}/",
        "/admin/settings/service-providers": "/docs/admin-guide/service-providers/",
        "/admin/settings/branding": "/docs/admin-guide/branding/",
        "/admin/groups": "/docs/admin-guide/groups/",
        "/admin/audit": "/docs/admin-guide/audit/",
        "/admin/integrations": "/docs/admin-guide/integrations/",
    }
    for path, expected_docs in cases.items():
        page = get_page_by_path(path)
        assert page.docs_path == expected_docs, f"{path} docs_path mismatch"


def test_docs_path_set_on_user_pages():
    """Test that user-facing pages have docs_path values."""
    cases = {
        "/account/profile": "/docs/user-guide/profile/",
        "/account/mfa": "/docs/user-guide/two-step-verification/",
        "/account/background-jobs": "/docs/user-guide/background-jobs/",
        "/users": "/docs/admin-guide/users/",
    }
    for path, expected_docs in cases.items():
        page = get_page_by_path(path)
        assert page.docs_path == expected_docs, f"{path} docs_path mismatch"


def test_docs_path_set_on_sp_detail_tabs():
    """Test that SP detail tabs have specific docs_path values."""
    sp = "/admin/settings/service-providers/detail"
    docs = "/docs/admin-guide/service-providers"
    cases = {
        f"{sp}/details": f"{docs}/registering-an-sp/",
        f"{sp}/attributes": f"{docs}/attribute-mapping/",
        f"{sp}/certificates": f"{docs}/sp-certificates/",
        f"{sp}/metadata": f"{docs}/registering-an-sp/",
    }
    for path, expected_docs in cases.items():
        page = get_page_by_path(path)
        assert page.docs_path == expected_docs, f"{path} docs_path mismatch"


def test_docs_path_set_on_group_detail_tabs():
    """Test that group detail tabs have specific docs_path values."""
    cases = {
        "/admin/groups/detail/membership": "/docs/admin-guide/groups/membership-management/",
        "/admin/groups/detail/applications": "/docs/admin-guide/groups/group-based-access/",
        "/admin/groups/detail/relationships": "/docs/admin-guide/groups/group-hierarchy/",
    }
    for path, expected_docs in cases.items():
        page = get_page_by_path(path)
        assert page.docs_path == expected_docs, f"{path} docs_path mismatch"


def test_navigation_context_docs_path_direct():
    """Test that navigation context returns docs_path for pages that define it."""
    context = get_navigation_context("/dashboard", "member")
    assert context["docs_path"] == "/docs/user-guide/dashboard/"


def test_navigation_context_docs_path_inherited():
    """Test that child pages inherit docs_path from nearest ancestor."""
    # /admin/groups/list has no docs_path, but parent /admin/groups does
    context = get_navigation_context("/admin/groups/list", "admin")
    assert context["docs_path"] == "/docs/admin-guide/groups/"


def test_navigation_context_docs_path_child_overrides_parent():
    """Test that a child's own docs_path overrides the parent's."""
    # /admin/groups/detail/membership has its own docs_path
    context = get_navigation_context("/admin/groups/detail/membership", "admin")
    assert context["docs_path"] == "/docs/admin-guide/groups/membership-management/"


def test_navigation_context_docs_path_none_when_unset():
    """Test that docs_path is None when neither page nor ancestors define it."""
    context = get_navigation_context("/login", None)
    assert context["docs_path"] is None


def test_navigation_context_docs_path_unknown_path():
    """Test that docs_path is None for unknown paths."""
    context = get_navigation_context("/unknown-path", "member")
    assert context["docs_path"] is None


def test_navigation_context_docs_path_idp_detail_inherited():
    """Test IdP detail tabs inherit from IdP detail parent."""
    # /admin/settings/identity-providers/idp/details has no docs_path,
    # but its parent /admin/settings/identity-providers/idp does
    context = get_navigation_context(
        "/admin/settings/identity-providers/idp/details", "super_admin"
    )
    assert context["docs_path"] == "/docs/admin-guide/identity-providers/saml-setup/"
