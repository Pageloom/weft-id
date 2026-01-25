"""Middleware that populates request context for all requests.

This middleware extracts request metadata (IP, user agent, device, session)
at the start of each request and stores it in a contextvar. The log_event
function automatically reads from this contextvar, ensuring all events
logged during web requests have complete context.
"""

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from utils.request_context import clear_request_context, set_request_context
from utils.request_metadata import extract_request_metadata


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Automatically populate request context for all web requests."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Extract request metadata and set it in contextvar."""
        metadata = extract_request_metadata(request)
        set_request_context(metadata)
        try:
            return await call_next(request)
        finally:
            clear_request_context()
