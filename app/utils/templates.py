"""Shared Jinja2Templates instance with application-wide globals.

All routers should import `templates` from here rather than creating their own
Jinja2Templates instances, so that globals registered here (e.g. static_url)
are available in every template without being passed explicitly per-request.
"""

from pathlib import Path

from fastapi.templating import Jinja2Templates
from utils.static_assets import static_url

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
templates.env.globals["static_url"] = static_url
