"""Hierarchical page structure configuration for Loom.

This module defines all pages and their organization within the application.
Each page definition includes routing info, permissions, and navigation structure.
"""

from dataclasses import dataclass
from enum import Enum


class PagePermission(str, Enum):
    """Permission levels for pages."""

    PUBLIC = 'public'  # Accessible to everyone
    AUTHENTICATED = 'authenticated'  # Requires login
    ADMIN = 'admin'  # Requires admin role


@dataclass
class Page:
    """Represents a page in the application."""

    path: str
    title: str
    permission: PagePermission
    icon: str | None = None
    show_in_nav: bool = True
    children: list['Page'] | None = None

    def get_all_paths(self) -> list[str]:
        """Get all paths including children."""
        paths = [self.path]
        if self.children:
            for child in self.children:
                paths.extend(child.get_all_paths())
        return paths


# Define the page hierarchy
PAGES = [
    Page(
        path='/dashboard',
        title='Dashboard',
        permission=PagePermission.AUTHENTICATED,
        icon='home',
        show_in_nav=True,
    ),
    Page(
        path='/users',
        title='Users',
        permission=PagePermission.ADMIN,
        icon='users',
        show_in_nav=True,
        children=[
            Page(
                path='/users',
                title='User List',
                permission=PagePermission.ADMIN,
                show_in_nav=False,
            ),
        ],
    ),
    Page(
        path='/settings',
        title='Settings',
        permission=PagePermission.AUTHENTICATED,
        icon='settings',
        show_in_nav=True,
        children=[
            Page(
                path='/settings/profile',
                title='Profile',
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
            ),
            Page(
                path='/settings/emails',
                title='Email Addresses',
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
            ),
            Page(
                path='/settings/mfa',
                title='MFA Settings',
                permission=PagePermission.AUTHENTICATED,
                show_in_nav=True,
            ),
        ],
    ),
]


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
        if page.permission == PagePermission.PUBLIC:
            nav_items.append(page)
        elif page.permission == PagePermission.AUTHENTICATED and user_role:
            nav_items.append(page)
        elif page.permission == PagePermission.ADMIN and user_role == 'admin':
            nav_items.append(page)

    return nav_items
