"""Hierarchical page structure configuration for Loom.

This module defines all pages and their organization within the application.
Each page definition includes routing info, permissions, and navigation structure.
"""

from dataclasses import dataclass
from enum import Enum


class PagePermission(str, Enum):
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
    # Admin menu (merged Settings + Admin)
    Page(
        path="/admin",
        title="Admin",
        permission=PagePermission.ADMIN,
        icon="shield",
        show_in_nav=True,
        children=[
            Page(
                path="/admin/security",
                title="Security",
                permission=PagePermission.SUPER_ADMIN,
                show_in_nav=True,
            ),
            Page(
                path="/admin/privileged-domains",
                title="Privileged Domains",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
            ),
            Page(
                path="/admin/events",
                title="Event Log",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
            ),
            Page(
                path="/admin/events/detail",
                title="Event Details",
                permission=PagePermission.ADMIN,
                show_in_nav=False,
                creates_nav_level=False,
            ),
            Page(
                path="/admin/reactivation-requests",
                title="Reactivation Requests",
                permission=PagePermission.ADMIN,
                show_in_nav=True,
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
    """Get the first accessible child page for a given parent path."""
    page = get_page_by_path(path)

    if not page or not page.children:
        return None

    # Find first child that user has permission to access and is shown in nav
    for child in page.children:
        if child.show_in_nav and has_permission(child, user_role):
            return child.path

    return None
