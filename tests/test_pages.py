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
    assert "/security" in paths


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
    settings_page = get_page_by_path("/identity-providers/domain-routing")
    assert not has_permission(settings_page, None)
    assert not has_permission(settings_page, "member")
    assert has_permission(settings_page, "admin")
    assert has_permission(settings_page, "super_admin")


def test_has_permission_super_admin():
    """Test super_admin pages require super_admin role."""
    security_page = get_page_by_path("/security")
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
    assert not has_page_access("/identity-providers/domain-routing", None)
    assert not has_page_access("/identity-providers/domain-routing", "member")
    assert has_page_access("/identity-providers/domain-routing", "admin")
    assert has_page_access("/identity-providers/domain-routing", "super_admin")


def test_has_page_access_super_admin_page():
    """Test page access check for super_admin pages."""
    assert not has_page_access("/security", None)
    assert not has_page_access("/security", "member")
    assert not has_page_access("/security", "admin")
    assert has_page_access("/security", "super_admin")


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
    assert "/directory" in paths
    assert "/security" not in paths  # Admin only
    assert "/identity-providers" not in paths  # Admin only


def test_get_nav_items_admin():
    """Test navigation items for admin."""
    nav_items = get_nav_items("admin")

    paths = [item.path for item in nav_items]
    assert "/dashboard" in paths
    assert "/directory" in paths
    assert "/identity-providers" in paths  # Container permission is ADMIN
    assert "/applications" in paths  # Container permission is ADMIN
    assert "/audit" in paths
    assert "/settings" in paths
    assert "/security" not in paths  # Super admin only


def test_get_nav_items_super_admin():
    """Test navigation items for super_admin."""
    nav_items = get_nav_items("super_admin")

    paths = [item.path for item in nav_items]
    assert "/dashboard" in paths
    assert "/directory" in paths
    assert "/identity-providers" in paths
    assert "/applications" in paths
    assert "/security" in paths
    assert "/audit" in paths
    assert "/settings" in paths


def test_seven_top_level_nav_items_for_super_admin():
    """Full nav is exactly 7 top-level items for super_admin.

    Dashboard, Directory, Identity Providers, Applications, Security, Audit,
    Settings -- see the target path map in
    .claude/ITERATION_nav_restructure.md.
    """
    nav_items = get_nav_items("super_admin")
    paths = [item.path for item in nav_items]
    assert paths == [
        "/dashboard",
        "/directory",
        "/identity-providers",
        "/applications",
        "/security",
        "/audit",
        "/settings",
    ]


def test_get_first_accessible_child_account_member():
    """Test getting first accessible child for account."""
    first_child = get_first_accessible_child("/account", "member")
    assert first_child == "/account/profile"


def test_get_first_accessible_child_users_member():
    """Test getting first accessible child for users."""
    first_child = get_first_accessible_child("/users", "member")
    assert first_child == "/users/list"


def test_get_first_accessible_child_settings_menu_unaffected_by_role():
    """Settings is narrowed to Branding + About, both ADMIN -- same first child for both roles."""
    assert get_first_accessible_child("/settings", "admin") == "/settings/branding/global"
    assert get_first_accessible_child("/settings", "super_admin") == "/settings/branding/global"


def test_get_first_accessible_child_security_menu_super_admin_only():
    """Security is entirely super_admin-only, so a plain admin sees nothing."""
    assert get_first_accessible_child("/security", "super_admin") == "/security/sessions"
    assert get_first_accessible_child("/security", "admin") is None


def test_get_first_accessible_child_audit_menu_by_role():
    """Event Log is ADMIN, so both admin and super_admin land there first."""
    assert get_first_accessible_child("/audit", "admin") == "/audit/events"
    assert get_first_accessible_child("/audit", "super_admin") == "/audit/events"


def test_get_first_accessible_child_no_permission():
    """Test getting None when user has no permission to any children."""
    first_child = get_first_accessible_child("/security", "member")
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
    # Member should not see admin-only sub-sub-items
    context_member = get_navigation_context("/users/list", "member")
    sub_sub_nav_paths_member = [item.path for item in context_member["sub_sub_nav_items"]]

    # Admin should see admin sub-sub-items
    context_admin = get_navigation_context("/users/list", "admin")
    sub_sub_nav_paths_admin = [item.path for item in context_admin["sub_sub_nav_items"]]

    # Both should see /users/list (nested under Directory > Users)
    assert "/users/list" in sub_sub_nav_paths_member
    assert "/users/list" in sub_sub_nav_paths_admin


def test_get_navigation_context_top_level_items():
    """Test navigation context includes top-level nav items."""
    context = get_navigation_context("/dashboard", "admin")

    top_level_paths = [item.path for item in context["top_level_items"]]
    assert "/dashboard" in top_level_paths
    assert "/directory" in top_level_paths
    assert "/audit" in top_level_paths
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
    # profile, password, emails, mfa, background-jobs
    assert len(account_page.children) == 5


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
    admin_page = get_page_by_path("/identity-providers/domain-routing")
    super_admin_page = get_page_by_path("/security")

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
    """Test that the Security and Identity Providers pages have appropriate permissions."""
    # Security (super_admin only) -- top-level since Iteration 4, no longer
    # nested under /admin
    security_page = get_page_by_path("/security")
    assert security_page is not None
    assert security_page.permission == PagePermission.SUPER_ADMIN

    # Domain Routing (admin) -- lives under the top-level Identity Providers
    # container, not /admin, since the nav restructure
    domain_routing = get_page_by_path("/identity-providers/domain-routing")
    assert domain_routing is not None
    assert domain_routing.permission == PagePermission.ADMIN


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
# Applications Pages Tests (nav_restructure Iteration 3)
# =============================================================================


def test_applications_container_permission_is_admin():
    """The Applications container is ADMIN, not SUPER_ADMIN.

    OAuth2 / OIDC is ADMIN-accessible, which pins the container's own
    permission down to ADMIN per the permission fidelity rule, even though
    its SAML, Forward Auth, and Service Accounts siblings are SUPER_ADMIN.
    """
    page = get_page_by_path("/applications")
    assert page is not None
    assert page.title == "Applications"
    assert page.permission == PagePermission.ADMIN
    assert page.show_in_nav is True
    assert not has_page_access("/applications", "member")
    assert has_page_access("/applications", "admin")
    assert has_page_access("/applications", "super_admin")


def test_applications_children_structure():
    """Test the Applications page has the four expected children."""
    page = get_page_by_path("/applications")
    assert page.children is not None
    assert len(page.children) == 4

    child_paths = [child.path for child in page.children]
    assert child_paths == [
        "/applications/saml",
        "/applications/oauth",
        "/applications/forward-auth",
        "/applications/service-accounts",
    ]


def test_saml_moved_from_admin_settings_service_providers():
    """SAML service providers moved from /admin/settings/service-providers."""
    assert get_page_by_path("/admin/settings/service-providers") is None
    assert not has_page_access("/admin/settings/service-providers", "super_admin")
    page = get_page_by_path("/applications/saml")
    assert page is not None
    assert page.title == "SAML"
    assert page.permission == PagePermission.SUPER_ADMIN
    assert not has_page_access("/applications/saml", "admin")
    assert has_page_access("/applications/saml", "super_admin")


def test_saml_sp_detail_children_keep_super_admin_permission():
    """Details, Attributes, Groups, SCIM, Certificates, Metadata, Danger stay SUPER_ADMIN."""
    for path in (
        "/applications/saml/new",
        "/applications/saml/detail/details",
        "/applications/saml/detail/attributes",
        "/applications/saml/detail/groups",
        "/applications/saml/detail/scim",
        "/applications/saml/detail/certificates",
        "/applications/saml/detail/metadata",
        "/applications/saml/detail/danger",
    ):
        page = get_page_by_path(path)
        assert page is not None, f"{path} not registered"
        assert page.permission == PagePermission.SUPER_ADMIN
        assert not has_page_access(path, "admin")
        assert has_page_access(path, "super_admin")


def test_oauth_moved_from_admin_integrations_apps_and_renamed():
    """OAuth2 / OIDC apps moved from /admin/integrations/apps, renamed."""
    assert get_page_by_path("/admin/integrations/apps") is None
    assert not has_page_access("/admin/integrations/apps", "admin")
    page = get_page_by_path("/applications/oauth")
    assert page is not None
    assert page.title == "OAuth2 / OIDC"
    assert page.permission == PagePermission.ADMIN
    assert has_page_access("/applications/oauth", "admin")
    assert not has_page_access("/applications/oauth", "member")


def test_forward_auth_tabs_domains_and_apps():
    """Protected Domains and Proxy Apps render as Domains | Apps tabs."""
    assert get_page_by_path("/admin/settings/protected-domains") is None
    assert get_page_by_path("/admin/settings/proxy-apps") is None

    container = get_page_by_path("/applications/forward-auth")
    assert container is not None
    assert container.title == "Forward Auth"
    assert container.permission == PagePermission.SUPER_ADMIN
    assert container.children is not None

    child_paths = [child.path for child in container.children]
    assert child_paths == [
        "/applications/forward-auth/domains",
        "/applications/forward-auth/apps",
    ]

    domains = get_page_by_path("/applications/forward-auth/domains")
    apps = get_page_by_path("/applications/forward-auth/apps")
    assert domains is not None and domains.title == "Domains"
    assert apps is not None and apps.title == "Apps"
    assert domains.permission == PagePermission.SUPER_ADMIN
    assert apps.permission == PagePermission.SUPER_ADMIN

    assert get_page_by_path("/applications/forward-auth/domains/detail") is not None
    assert get_page_by_path("/applications/forward-auth/apps/detail") is not None


def test_service_accounts_moved_from_admin_integrations_b2b_and_renamed():
    """B2B service accounts moved from /admin/integrations/b2b, renamed."""
    assert get_page_by_path("/admin/integrations/b2b") is None
    assert not has_page_access("/admin/integrations/b2b", "super_admin")
    page = get_page_by_path("/applications/service-accounts")
    assert page is not None
    assert page.title == "Service Accounts"
    assert page.permission == PagePermission.SUPER_ADMIN
    assert has_page_access("/applications/service-accounts", "super_admin")
    assert not has_page_access("/applications/service-accounts", "admin")


def test_integrations_container_removed():
    """The old /admin/integrations container no longer exists, nor does /admin."""
    assert get_page_by_path("/admin/integrations") is None
    assert get_page_by_path("/admin") is None


def test_applications_first_accessible_child_by_role():
    """OAuth2 / OIDC is the only child a plain admin can see; super_admin sees SAML."""
    assert get_first_accessible_child("/applications", "admin") == "/applications/oauth"
    assert get_first_accessible_child("/applications", "super_admin") == "/applications/saml"


def test_applications_get_all_paths():
    """Test get_all_paths includes all Applications pages."""
    page = get_page_by_path("/applications")
    all_paths = page.get_all_paths()

    assert "/applications" in all_paths
    assert "/applications/saml" in all_paths
    assert "/applications/oauth" in all_paths
    assert "/applications/forward-auth" in all_paths
    assert "/applications/forward-auth/domains" in all_paths
    assert "/applications/forward-auth/apps" in all_paths
    assert "/applications/service-accounts" in all_paths


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
    sec = "/security"
    idp = "/docs/admin-guide/identity-providers"
    cases = {
        sec: "/docs/admin-guide/security/",
        f"{sec}/sessions": "/docs/admin-guide/security/sessions/",
        f"{sec}/certificates": "/docs/admin-guide/security/certificates/",
        f"{sec}/permissions": "/docs/admin-guide/security/permissions/",
        "/identity-providers/domain-routing": f"{idp}/privileged-domains/",
        "/identity-providers/saml": f"{idp}/",
        "/applications/saml": "/docs/admin-guide/service-providers/",
        "/applications/oauth": "/docs/admin-guide/integrations/apps/",
        "/applications/service-accounts": "/docs/admin-guide/integrations/b2b/",
        "/settings/branding": "/docs/admin-guide/branding/",
        "/groups": "/docs/admin-guide/groups/",
        "/audit": "/docs/admin-guide/audit/",
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
    sp = "/applications/saml/detail"
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
        "/groups/detail/membership": "/docs/admin-guide/groups/membership-management/",
        "/groups/detail/applications": "/docs/admin-guide/groups/group-based-access/",
        "/groups/detail/relationships": "/docs/admin-guide/groups/group-hierarchy/",
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
    # /groups/list has no docs_path, but parent /groups does
    context = get_navigation_context("/groups/list", "admin")
    assert context["docs_path"] == "/docs/admin-guide/groups/"


def test_navigation_context_docs_path_child_overrides_parent():
    """Test that a child's own docs_path overrides the parent's."""
    # /groups/detail/membership has its own docs_path
    context = get_navigation_context("/groups/detail/membership", "admin")
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
    # /identity-providers/saml/idp/details has no docs_path,
    # but its parent /identity-providers/saml/idp does
    context = get_navigation_context("/identity-providers/saml/idp/details", "super_admin")
    assert context["docs_path"] == "/docs/admin-guide/identity-providers/saml-setup/"


# =============================================================================
# Directory Container Permission Fidelity (nav_restructure Iteration 1)
# =============================================================================


def test_directory_container_page_exists_and_is_authenticated():
    """The Directory container itself is AUTHENTICATED so it never disappears."""
    page = get_page_by_path("/directory")
    assert page is not None
    assert page.title == "Directory"
    assert page.permission == PagePermission.AUTHENTICATED
    assert has_page_access("/directory", "member")
    assert has_page_access("/directory", "admin")
    assert has_page_access("/directory", "super_admin")
    assert not has_page_access("/directory", None)


def test_groups_container_moved_to_top_level_keeps_admin_permission():
    """Groups moved from /admin/groups to /groups but kept its ADMIN permission."""
    assert get_page_by_path("/admin/groups") is None
    page = get_page_by_path("/groups")
    assert page is not None
    assert page.permission == PagePermission.ADMIN
    assert not has_page_access("/groups", "member")
    assert has_page_access("/groups", "admin")
    assert has_page_access("/groups", "super_admin")


def test_requests_container_moved_and_renamed_keeps_admin_permission():
    """Todo -> Requests moved to /directory/requests, permission unchanged (ADMIN)."""
    assert get_page_by_path("/admin/todo") is None
    page = get_page_by_path("/directory/requests")
    assert page is not None
    assert page.title == "Requests"
    assert page.permission == PagePermission.ADMIN
    assert not has_page_access("/directory/requests", "member")
    assert has_page_access("/directory/requests", "admin")


def test_requests_children_keep_admin_permission():
    """Reactivation, its history tab, and User Attributes all stay ADMIN."""
    for path in (
        "/directory/requests/reactivation",
        "/directory/requests/reactivation/history",
        "/directory/requests/user-attributes",
    ):
        page = get_page_by_path(path)
        assert page is not None, f"{path} not registered"
        assert page.permission == PagePermission.ADMIN
        assert not has_page_access(path, "member")
        assert has_page_access(path, "admin")


def test_attributes_page_moved_keeps_super_admin_permission():
    """Settings > User attributes -> /directory/attributes, still SUPER_ADMIN only."""
    assert get_page_by_path("/admin/settings/user-attributes") is None
    page = get_page_by_path("/directory/attributes")
    assert page is not None
    assert page.permission == PagePermission.SUPER_ADMIN
    assert not has_page_access("/directory/attributes", "admin")
    assert has_page_access("/directory/attributes", "super_admin")


def test_exports_page_moved_keeps_admin_permission():
    """Audit > User Export -> /directory/exports, still ADMIN (unchanged)."""
    assert get_page_by_path("/admin/audit/user-export") is None
    page = get_page_by_path("/directory/exports")
    assert page is not None
    assert page.permission == PagePermission.ADMIN
    assert not has_page_access("/directory/exports", "member")
    assert has_page_access("/directory/exports", "admin")


def test_users_new_add_user_removed_from_nav_but_permission_unchanged():
    """Add User is now a button, not a nav item, but keeps its ADMIN permission."""
    page = get_page_by_path("/users/new")
    assert page is not None
    assert page.permission == PagePermission.ADMIN
    assert page.show_in_nav is False


def test_groups_new_add_group_removed_from_nav_but_permission_unchanged():
    """Add Group is now a button, not a nav item, but keeps its ADMIN permission."""
    page = get_page_by_path("/groups/new")
    assert page is not None
    assert page.permission == PagePermission.ADMIN
    assert page.show_in_nav is False


# =============================================================================
# Identity Providers Container Permission Fidelity (nav_restructure Iteration 2)
# =============================================================================


def test_identity_providers_container_permission_is_admin():
    """The Identity Providers container is ADMIN, not SUPER_ADMIN.

    Domain Routing is ADMIN-accessible, which pins the container's own
    permission down to ADMIN per the permission fidelity rule, even though
    its SAML and OIDC siblings are SUPER_ADMIN only.
    """
    page = get_page_by_path("/identity-providers")
    assert page is not None
    assert page.title == "Identity Providers"
    assert page.permission == PagePermission.ADMIN
    assert not has_page_access("/identity-providers", "member")
    assert has_page_access("/identity-providers", "admin")
    assert has_page_access("/identity-providers", "super_admin")


def test_saml_and_oidc_are_sibling_tabs_with_symmetric_naming():
    """SAML and OIDC are children of Identity Providers with parallel titles."""
    saml_page = get_page_by_path("/identity-providers/saml")
    oidc_page = get_page_by_path("/identity-providers/oidc")
    assert saml_page is not None
    assert oidc_page is not None
    assert saml_page.title == "SAML"
    assert oidc_page.title == "OIDC"
    assert saml_page.permission == PagePermission.SUPER_ADMIN
    assert oidc_page.permission == PagePermission.SUPER_ADMIN

    container = get_page_by_path("/identity-providers")
    assert container is not None
    assert container.children is not None
    child_paths = [child.path for child in container.children]
    assert "/identity-providers/saml" in child_paths
    assert "/identity-providers/oidc" in child_paths
    assert "/identity-providers/domain-routing" in child_paths


def test_saml_moved_from_admin_settings_keeps_super_admin_permission():
    """SAML identity providers moved from /admin/settings/identity-providers."""
    assert get_page_by_path("/admin/settings/identity-providers") is None
    assert not has_page_access("/admin/settings/identity-providers", "super_admin")
    assert has_page_access("/identity-providers/saml", "super_admin")
    assert not has_page_access("/identity-providers/saml", "admin")


def test_saml_idp_detail_children_keep_super_admin_permission():
    """Details, Certificates, Attributes, Metadata, SCIM, Disable/Delete stay SUPER_ADMIN."""
    for path in (
        "/identity-providers/saml/new",
        "/identity-providers/saml/idp/details",
        "/identity-providers/saml/idp/certificates",
        "/identity-providers/saml/idp/attributes",
        "/identity-providers/saml/idp/metadata",
        "/identity-providers/saml/idp/scim",
        "/identity-providers/saml/idp/danger",
    ):
        page = get_page_by_path(path)
        assert page is not None, f"{path} not registered"
        assert page.permission == PagePermission.SUPER_ADMIN
        assert not has_page_access(path, "admin")
        assert has_page_access(path, "super_admin")


def test_oidc_moved_from_admin_settings_keeps_super_admin_permission():
    """OIDC identity providers moved from /admin/settings/oidc-identity-providers."""
    assert get_page_by_path("/admin/settings/oidc-identity-providers") is None
    assert not has_page_access("/admin/settings/oidc-identity-providers", "super_admin")
    assert has_page_access("/identity-providers/oidc", "super_admin")
    assert not has_page_access("/identity-providers/oidc", "admin")


def test_oidc_connection_detail_children_keep_super_admin_permission():
    """Add, Details, Claim Mapping, Disable/Delete all stay SUPER_ADMIN."""
    for path in (
        "/identity-providers/oidc/new",
        "/identity-providers/oidc/connection/details",
        "/identity-providers/oidc/connection/claim-mapping",
        "/identity-providers/oidc/connection/danger",
    ):
        page = get_page_by_path(path)
        assert page is not None, f"{path} not registered"
        assert page.permission == PagePermission.SUPER_ADMIN
        assert not has_page_access(path, "admin")
        assert has_page_access(path, "super_admin")


def test_domain_routing_moved_and_renamed_keeps_admin_permission():
    """Privileged Domains -> Domain Routing, moved and renamed, still ADMIN."""
    assert get_page_by_path("/admin/settings/privileged-domains") is None
    page = get_page_by_path("/identity-providers/domain-routing")
    assert page is not None
    assert page.title == "Domain Routing"
    assert page.permission == PagePermission.ADMIN
    assert not has_page_access("/identity-providers/domain-routing", "member")
    assert has_page_access("/identity-providers/domain-routing", "admin")


def test_identity_providers_first_accessible_child_by_role():
    """Domain Routing is the only child an admin can see; super_admin sees SAML."""
    assert get_first_accessible_child("/identity-providers", "admin") == (
        "/identity-providers/domain-routing"
    )
    assert get_first_accessible_child("/identity-providers", "super_admin") == (
        "/identity-providers/saml"
    )


# =============================================================================
# Security, Audit, Settings Promoted to Top-Level; /admin Removed
# (nav_restructure Iteration 4)
# =============================================================================


def test_security_promoted_to_top_level():
    """Security moved from /admin/settings/security to /security, unchanged permission."""
    assert get_page_by_path("/admin/settings/security") is None
    page = get_page_by_path("/security")
    assert page is not None
    assert page.title == "Security"
    assert page.permission == PagePermission.SUPER_ADMIN
    assert not has_page_access("/security", "admin")
    assert has_page_access("/security", "super_admin")


def test_security_children_keep_super_admin_permission():
    """Sessions, Certificates, Passwords, Permissions, Authentication all stay SUPER_ADMIN."""
    for path in (
        "/security/sessions",
        "/security/certificates",
        "/security/passwords",
        "/security/permissions",
        "/security/authentication",
    ):
        page = get_page_by_path(path)
        assert page is not None, f"{path} not registered"
        assert page.permission == PagePermission.SUPER_ADMIN
        assert not has_page_access(path, "admin")
        assert has_page_access(path, "super_admin")


def test_audit_promoted_to_top_level():
    """Audit moved from /admin/audit to /audit; User Export moved out in Iteration 1."""
    assert get_page_by_path("/admin/audit") is None
    page = get_page_by_path("/audit")
    assert page is not None
    assert page.title == "Audit"
    assert page.permission == PagePermission.ADMIN
    assert not has_page_access("/audit", "member")
    assert has_page_access("/audit", "admin")

    child_paths = [child.path for child in page.children]
    assert child_paths == ["/audit/events", "/audit/saml-debug"]


def test_audit_events_keeps_admin_permission():
    """Event Log stays ADMIN (unchanged from /admin/audit/events)."""
    assert get_page_by_path("/admin/audit/events") is None
    page = get_page_by_path("/audit/events")
    assert page is not None
    assert page.permission == PagePermission.ADMIN
    assert has_page_access("/audit/events", "admin")


def test_audit_saml_debug_stays_super_admin():
    """SAML Debug Log stays SUPER_ADMIN (unchanged from /admin/audit/saml-debug)."""
    assert get_page_by_path("/admin/audit/saml-debug") is None
    page = get_page_by_path("/audit/saml-debug")
    assert page is not None
    assert page.permission == PagePermission.SUPER_ADMIN
    assert not has_page_access("/audit/saml-debug", "admin")
    assert has_page_access("/audit/saml-debug", "super_admin")


def test_settings_narrowed_to_branding_and_about():
    """Settings narrowed to Branding + About, promoted to top-level from /admin/settings."""
    assert get_page_by_path("/admin/settings") is None
    page = get_page_by_path("/settings")
    assert page is not None
    assert page.title == "Settings"
    assert page.permission == PagePermission.ADMIN

    child_paths = [child.path for child in page.children]
    assert child_paths == ["/settings/branding", "/settings/about"]


def test_settings_branding_and_about_keep_admin_permission():
    """Branding (and its tabs) and About all stay ADMIN (unchanged)."""
    assert get_page_by_path("/admin/settings/branding") is None
    assert get_page_by_path("/admin/settings/about") is None
    for path in (
        "/settings/branding",
        "/settings/branding/global",
        "/settings/branding/groups",
        "/settings/about",
    ):
        page = get_page_by_path(path)
        assert page is not None, f"{path} not registered"
        assert page.permission == PagePermission.ADMIN
        assert not has_page_access(path, "member")
        assert has_page_access(path, "admin")


def test_admin_wrapper_fully_removed():
    """The /admin top-level page no longer exists as a concept."""
    assert get_page_by_path("/admin") is None
    assert not has_page_access("/admin", "super_admin")


def test_no_page_anywhere_in_the_registry_lives_under_admin():
    """Nothing may sit under /admin -- it survives only as a legacy redirect.

    The per-section tests each check one retired path; this catches any page
    reintroduced under /admin by later work, wherever it is nested.
    """
    offenders = [
        page.path
        for page in get_all_pages(PAGES)
        if page.path == "/admin" or page.path.startswith("/admin/")
    ]

    assert offenders == []


def test_security_get_all_paths():
    """Test get_all_paths includes all Security pages."""
    page = get_page_by_path("/security")
    all_paths = page.get_all_paths()
    assert all_paths == [
        "/security",
        "/security/sessions",
        "/security/certificates",
        "/security/passwords",
        "/security/permissions",
        "/security/authentication",
    ]


def test_audit_get_all_paths():
    """Test get_all_paths includes all Audit pages."""
    page = get_page_by_path("/audit")
    all_paths = page.get_all_paths()
    assert "/audit" in all_paths
    assert "/audit/events" in all_paths
    assert "/audit/events/detail" in all_paths
    assert "/audit/saml-debug" in all_paths
    assert "/audit/saml-debug/entry" in all_paths


def test_settings_get_all_paths():
    """Test get_all_paths includes all Settings pages."""
    page = get_page_by_path("/settings")
    all_paths = page.get_all_paths()
    assert all_paths == [
        "/settings",
        "/settings/branding",
        "/settings/branding/global",
        "/settings/branding/groups",
        "/settings/about",
    ]
