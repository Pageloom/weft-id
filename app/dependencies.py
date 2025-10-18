"""FastAPI dependencies for request handling."""

from typing import cast

import database
import settings
from fastapi import HTTPException, Request


def normalize_host(h: str | None) -> str:
    """Normalize host header by removing port and trailing dots."""
    h = (h or "").split(":")[0].rstrip(".").lower()
    return h


def get_tenant_id_from_request(request: Request) -> str:
    """Extract tenant ID from request hostname."""
    host = normalize_host(request.headers.get("x-forwarded-host") or request.headers.get("host"))

    if not host.endswith(f".{settings.BASE_DOMAIN}"):
        raise HTTPException(status_code=404, detail="Unknown host")

    subdomain = host.split(".")[0]

    row = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )

    if not row:
        raise HTTPException(status_code=404, detail=f"No tenant configured for host {host}")

    return cast(str, row["id"])
