"""Shared Jinja2Templates instance with application-wide globals.

All routers should import `templates` from here rather than creating their own
Jinja2Templates instances, so that globals registered here (e.g. static_url)
are available in every template without being passed explicitly per-request.
"""

import re
from functools import lru_cache
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from utils.static_assets import static_url

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_ICONS_DIR = _TEMPLATES_DIR / "icons"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
templates.env.globals["static_url"] = static_url


@lru_cache(maxsize=64)
def _read_icon(name: str) -> str:
    path = _ICONS_DIR / f"{name}.svg"
    return path.read_text()


def icon(name: str, **kwargs: str) -> Markup:
    """Return an SVG icon with caller-supplied HTML attributes.

    Usage in templates:
        {{ icon("chevron-down", class="w-4 h-4 text-gray-400") }}
        {{ icon("chevron-down", class="w-4 h-4", id="filter-chevron") }}
    """
    svg = _read_icon(name)
    attrs = " ".join(f'{k}="{v}"' for k, v in kwargs.items() if v)
    if attrs:
        svg = re.sub(r"<svg\b", f"<svg {attrs}", svg, count=1)
    return Markup(svg)


templates.env.globals["icon"] = icon

_ROLE_LABELS = {
    "super_admin": "Super Admin",
    "admin": "Admin",
    "user": "User",
}


def display_role(role: str) -> str:
    """Format a raw role value for display (e.g. 'super_admin' → 'Super Admin')."""
    return _ROLE_LABELS.get(role, role.replace("_", " ").title())


templates.env.globals["display_role"] = display_role
