"""Hierarchical page structure configuration for Loom.

This module defines all pages and their organization within the application.
Each page definition includes routing info, permissions, and navigation structure.
"""

from dataclasses import dataclass
from enum import StrEnum


class PagePermission(StrEnum):
    """Permission levels for pages."""

    PUBLIC = "public"  # Accessible to everyone
    AUTHENTICATED = "authenticated"  # Requires login
    ADMIN = "admin"  # Requires admin role
    SUPER_ADMIN = "super_admin"  # Requires super admin role


@dataclass
class Page:
    """Represents a page in the application."""

    path: str
    title: str
    permission: PagePermission
    icon: str | None = None
    show_in_nav: bool = True
    creates_nav_level: bool = True
    children: list["Page"] | None = None

    def get_all_paths(self) -> list[str]:
        """Get all paths including children."""
        paths = [self.path]
        if self.children:
            for child in self.children:
                paths.extend(child.get_all_paths())
        return paths


# Define the page hierarchy
PAGES = [
    # Authentication pages
    Page(
        path="/login",
        title="Login",
        permission=PagePermission.PUBLIC,
        show_in_nav=False,
        creates_nav_level=False,
    ),
    Page(
        path="/dashboard",
        title="Dashboard",
        permission=PagePermission.AUTHENTICATED,
        icon="home",
        show_in_nav=True,
    ),
    # User management
    Page(
        path="/users",
        title="Users",
        permission=PagePermission.AUTHENTICATED,
        icon="users",
        show_in_nav=True,
        children=[
            Page(
                path="/users/list",
                title="User List",
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
            ),
            Page(
                path="/users/new",
                title="Add User",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
            ),
            Page(
                path="/users/user",
                title="User Details",
                permission=PagePermission.ADMIN,
                show_in_nav=False,
                creates_nav_level=False,
            ),
        ],
    ),
    Page(
        path="/account",
        title="User Settings",
        permission=PagePermission.AUTHENTICATED,
        icon="user",
        show_in_nav=False,
        children=[
            Page(
                path="/account/profile",
                title="Profile",
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
            ),
            Page(
                path="/account/emails",
                title="Email Addresses",
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
            ),
            Page(
                path="/account/mfa",
                title="MFA Settings",
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
                children=[
                    Page(
                        path="/account/mfa/setup/totp",
                        title="Setup Authenticator",
                        permission=PagePermission.AUTHENTICATED,
                        show_in_nav=False,
                        creates_nav_level=False,
                    ),
                    Page(
                        path="/account/mfa/downgrade-verify",
                        title="Verify MFA Downgrade",
                        permission=PagePermission.AUTHENTICATED,
                        show_in_nav=False,
                        creates_nav_level=False,
                    ),
                ],
            ),
            Page(
                path="/account/background-jobs",
                title="Background Jobs",
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
                children=[
                    Page(
                        path="/account/background-jobs/job",
                        title="Job Output",
                        permission=PagePermission.AUTHENTICATED,
                        show_in_nav=False,
                        creates_nav_level=False,
                    ),
                ],
            ),
        ],
    ),
    # Admin menu - organized into Settings, Todo, Audit, Integrations
    Page(
        path="/admin",
        title="Admin",
        permission=PagePermission.ADMIN,
        icon="shield",
        show_in_nav=True,
        children=[
            # Settings section: Security, Privileged Domains, Identity Providers
            Page(
                path="/admin/settings",
                title="Settings",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
                children=[
                    Page(
                        path="/admin/settings/security",
                        title="Security",
                        permission=PagePermission.SUPER_ADMIN,
                        show_in_nav=True,
                    ),
                    Page(
                        path="/admin/settings/privileged-domains",
                        title="Privileged Domains",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                    ),
                    Page(
                        path="/admin/settings/identity-providers",
                        title="Identity Providers",
                        permission=PagePermission.SUPER_ADMIN,
                        show_in_nav=True,
                        children=[
                            Page(
                                path="/admin/settings/identity-providers/new",
                                title="Add Identity Provider",
                                permission=PagePermission.SUPER_ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/settings/identity-providers/idp",
                                title="Identity Provider Details",
                                permission=PagePermission.SUPER_ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                                children=[
                                    Page(
                                        path="/admin/settings/identity-providers/idp/details",
                                        title="Details",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/identity-providers/idp/certificates",
                                        title="Certificates",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/identity-providers/idp/attributes",
                                        title="Attributes",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/identity-providers/idp/metadata",
                                        title="Metadata",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/identity-providers/idp/danger",
                                        title="Disable/Delete",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                ],
                            ),
                        ],
                    ),
                    Page(
                        path="/admin/settings/service-providers",
                        title="Service Providers",
                        permission=PagePermission.SUPER_ADMIN,
                        show_in_nav=True,
                        children=[
                            Page(
                                path="/admin/settings/service-providers/new",
                                title="Add Service Provider",
                                permission=PagePermission.SUPER_ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/settings/service-providers/detail",
                                title="Service Provider Details",
                                permission=PagePermission.SUPER_ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                                children=[
                                    Page(
                                        path="/admin/settings/service-providers/detail/details",
                                        title="Details",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/service-providers/detail/attributes",
                                        title="Attributes",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/service-providers/detail/groups",
                                        title="Groups",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/service-providers/detail/certificates",
                                        title="Certificates",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/service-providers/detail/metadata",
                                        title="Metadata",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                    Page(
                                        path="/admin/settings/service-providers/detail/danger",
                                        title="Disable/Delete",
                                        permission=PagePermission.SUPER_ADMIN,
                                        show_in_nav=False,
                                        creates_nav_level=False,
                                    ),
                                ],
                            ),
                        ],
                    ),
                    Page(
                        path="/admin/settings/branding",
                        title="Branding",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                    ),
                ],
            ),
            # Groups section: Group management
            Page(
                path="/admin/groups",
                title="Groups",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
                children=[
                    Page(
                        path="/admin/groups/list",
                        title="All Groups",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                    ),
                    Page(
                        path="/admin/groups/new",
                        title="Add Group",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                    ),
                    Page(
                        path="/admin/groups/detail",
                        title="Group Details",
                        permission=PagePermission.ADMIN,
                        show_in_nav=False,
                        creates_nav_level=False,
                        children=[
                            Page(
                                path="/admin/groups/detail/details",
                                title="Details",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/groups/detail/membership",
                                title="Membership",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/groups/detail/applications",
                                title="Applications",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/groups/detail/relationships",
                                title="Relationships",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/groups/detail/delete",
                                title="Delete",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/groups/members",
                                title="Group Members",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                            Page(
                                path="/admin/groups/members/add",
                                title="Add Members",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                        ],
                    ),
                ],
            ),
            # Todo section: Reactivation Requests
            Page(
                path="/admin/todo",
                title="Todo",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
                children=[
                    Page(
                        path="/admin/todo/reactivation",
                        title="Reactivation",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                        children=[
                            Page(
                                path="/admin/todo/reactivation/history",
                                title="Reactivation History",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                        ],
                    ),
                ],
            ),
            # Audit section: Event Log
            Page(
                path="/admin/audit",
                title="Audit",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
                children=[
                    Page(
                        path="/admin/audit/events",
                        title="Event Log",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                        children=[
                            Page(
                                path="/admin/audit/events/detail",
                                title="Event Details",
                                permission=PagePermission.ADMIN,
                                show_in_nav=False,
                                creates_nav_level=False,
                            ),
                        ],
                    ),
                ],
            ),
            # Integrations section: Apps, B2B
            Page(
                path="/admin/integrations",
                title="Integrations",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
                children=[
                    Page(
                        path="/admin/integrations/apps",
                        title="Apps",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                    ),
                    Page(
                        path="/admin/integrations/b2b",
                        title="B2B",
                        permission=PagePermission.ADMIN,
                        show_in_nav=True,
                    ),
                ],
            ),
        ],
    ),
    # MFA routes (under /mfa prefix) - these are workflow pages
    Page(
        path="/mfa",
        title="MFA",
        permission=PagePermission.PUBLIC,
        show_in_nav=False,
        children=[
            Page(
                path="/mfa/verify",
                title="MFA Verification",
                permission=PagePermission.PUBLIC,
                show_in_nav=False,
                creates_nav_level=False,
            ),
        ],
    ),
    # SAML authentication flow pages
    Page(
        path="/saml/select",
        title="Select Identity Provider",
        permission=PagePermission.PUBLIC,
        show_in_nav=False,
        creates_nav_level=False,
    ),
]


def get_all_pages(pages: list[Page]) -> list[Page]:
    """Recursively get all pages including nested children."""
    result = []
    for page in pages:
        result.append(page)
        if page.children:
            result.extend(get_all_pages(page.children))
    return result


def get_page_by_path(path: str) -> Page | None:
    """Find a page by its path."""

    def search(pages: list[Page], target: str) -> Page | None:
        for page in pages:
            if page.path == target:
                return page
            if page.children:
                result = search(page.children, target)
                if result:
                    return result
        return None

    return search(PAGES, path)


def get_nav_items(user_role: str | None = None) -> list[Page]:
    """Get navigation items filtered by user role."""
    nav_items = []

    for page in PAGES:
        if not page.show_in_nav:
            continue

        # Filter by permission
        if has_permission(page, user_role):
            nav_items.append(page)

    return nav_items


def get_navigation_context(path: str, user_role: str | None = None) -> dict:
    """Get navigation context for the current path.

    Returns a dict with:
    - current_page: The current page (or None)
    - nav_chain: List of pages from root to current (only pages that create nav levels)
    - top_level_items: All top-level navigation items
    - active_top_level: The active top-level page
    - sub_nav_items: Sub-navigation items for the active top-level
    - active_sub_level: The active sub-level page (if any)
    - sub_sub_nav_items: Sub-sub-navigation items (if any)
    """

    def find_page_with_ancestors(
        pages: list[Page], target_path: str, ancestors: list[Page] | None = None
    ) -> tuple[Page | None, list[Page]]:
        """Find a page and return it with its ancestors."""
        if ancestors is None:
            ancestors = []

        for page in pages:
            # Check for exact match
            if page.path == target_path:
                return page, ancestors

            # Check if target is under this page's path (prefix match for child routes)
            if target_path.startswith(page.path + "/") or (
                page.children and any(target_path.startswith(child.path) for child in page.children)
            ):
                if page.children:
                    result, chain = find_page_with_ancestors(
                        page.children, target_path, ancestors + [page]
                    )
                    if result:
                        return result, chain

                # If no child matched but path starts with this page's path, return this page
                if target_path.startswith(page.path):
                    return page, ancestors

        return None, ancestors

    # Find current page and its ancestors
    current_page, full_ancestors = find_page_with_ancestors(PAGES, path)

    # Build navigation chain (only pages that create nav levels)
    nav_chain = [p for p in full_ancestors if p.creates_nav_level]
    if current_page and current_page.creates_nav_level:
        nav_chain.append(current_page)

    # Get top-level items
    top_level_items = get_nav_items(user_role)

    # Determine active top-level page
    active_top_level = nav_chain[0] if nav_chain else None

    # Get sub-navigation items
    sub_nav_items = []
    active_sub_level = None
    sub_sub_nav_items = []

    if active_top_level and active_top_level.children:
        # Filter children by permission and show_in_nav
        sub_nav_items = [
            child
            for child in active_top_level.children
            if child.show_in_nav and has_permission(child, user_role)
        ]

        # Determine active sub-level
        if len(nav_chain) > 1:
            active_sub_level = nav_chain[1]

            # Get sub-sub-navigation items if available
            if active_sub_level and active_sub_level.children:
                sub_sub_nav_items = [
                    child
                    for child in active_sub_level.children
                    if child.show_in_nav and has_permission(child, user_role)
                ]

    return {
        "current_page": current_page,
        "nav_chain": nav_chain,
        "top_level_items": top_level_items,
        "active_top_level": active_top_level,
        "sub_nav_items": sub_nav_items,
        "active_sub_level": active_sub_level,
        "sub_sub_nav_items": sub_sub_nav_items,
    }


def has_permission(page: Page, user_role: str | None) -> bool:
    """Check if user has permission to access page.

    Permission hierarchy (higher roles can access lower level pages):
    - super_admin: can access super_admin, admin, authenticated, and public pages
    - admin: can access admin, authenticated, and public pages
    - authenticated: can access authenticated and public pages
    - None (not logged in): can only access public pages
    """
    if page.permission == PagePermission.PUBLIC:
        return True
    elif page.permission == PagePermission.AUTHENTICATED and user_role:
        return True
    elif page.permission == PagePermission.ADMIN and user_role in ("admin", "super_admin"):
        return True
    elif page.permission == PagePermission.SUPER_ADMIN and user_role == "super_admin":
        return True
    return False


def has_page_access(path: str, user_role: str | None) -> bool:
    """Check if user has permission to access a specific page path.

    This is the primary function that route handlers should use to verify access.

    Args:
        path: The page path to check (e.g., "/settings/privileged-domains")
        user_role: The user's role (e.g., "admin", "super_admin", or None)

    Returns:
        True if the user has permission to access the page, False otherwise
    """
    page = get_page_by_path(path)

    if not page:
        # If page is not defined in PAGES, deny access by default
        return False

    return has_permission(page, user_role)


def get_first_accessible_child(path: str, user_role: str | None = None) -> str | None:
    """Get the first accessible child page for a given parent path.

    If the child is a section container (has children with show_in_nav=True),
    recursively find the first accessible leaf page within that section.
    If the child has children but none are navigable (all show_in_nav=False),
    the child itself is a valid destination page.
    """
    page = get_page_by_path(path)

    if not page or not page.children:
        return None

    # Find first child that user has permission to access and is shown in nav
    for child in page.children:
        if child.show_in_nav and has_permission(child, user_role):
            # Check if this child has navigable children (show_in_nav=True)
            if child.children:
                # Only recurse if there are navigable children
                has_navigable_children = any(
                    c.show_in_nav and has_permission(c, user_role) for c in child.children
                )
                if has_navigable_children:
                    nested_child = get_first_accessible_child(child.path, user_role)
                    if nested_child:
                        return nested_child
                    # Shouldn't happen if has_navigable_children is true, but fallback
                    continue
            # Either no children, or children are all non-navigable (show_in_nav=False)
            # This page itself is the destination
            return child.path

    return None
