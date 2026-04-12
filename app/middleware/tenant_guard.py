"""Middleware that rejects requests without a valid tenant subdomain.

Requests to the bare domain (e.g., weft.id) or www subdomain are rejected
with HTTP 400 and a friendly HTML page. The /healthz endpoint is exempt.
"""

from collections.abc import Awaitable, Callable

import settings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.types import ASGIApp

# Paths that bypass tenant validation (infrastructure endpoints)
_EXEMPT_PATHS = frozenset({"/healthz", "/caddy/check-domain"})

_ERROR_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tenant Required</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; display: flex;
           justify-content: center; align-items: center; min-height: 100vh;
           margin: 0; background: #f9fafb; color: #374151; }
    .box  { text-align: center; max-width: 420px; padding: 2rem; }
    h1    { font-size: 1.25rem; margin-bottom: .5rem; }
    p     { font-size: .95rem; color: #6b7280; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Tenant subdomain required</h1>
    <p>This service requires a tenant subdomain in the URL
       (e.g., <strong>yourcompany.weft.id</strong>).
       Please check the URL and try again.</p>
  </div>
</body>
</html>"""


def _normalize_host(h: str | None) -> str:
    """Normalize host header by removing port and trailing dots."""
    return (h or "").split(":")[0].rstrip(".").lower()


class TenantGuardMiddleware(BaseHTTPMiddleware):
    """Reject requests that arrive without a recognized tenant subdomain."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Let exempt paths through regardless of host
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        base = settings.BASE_DOMAIN
        if not base:
            # BASE_DOMAIN not configured (e.g., test environment). Skip guard.
            return await call_next(request)

        host = _normalize_host(
            request.headers.get("x-forwarded-host") or request.headers.get("host")
        )

        # Reject bare domain
        if host == base:
            return HTMLResponse(content=_ERROR_HTML, status_code=400)

        # Reject www subdomain
        if host == f"www.{base}":
            return HTMLResponse(content=_ERROR_HTML, status_code=400)

        return await call_next(request)
