"""Security headers middleware to protect against common web vulnerabilities.

This middleware adds standard HTTP security headers to all responses:
- Content-Security-Policy: Prevents XSS and code injection attacks
- X-Frame-Options: Prevents clickjacking attacks
- X-Content-Type-Options: Prevents MIME sniffing attacks
- Strict-Transport-Security: Enforces HTTPS connections
- Referrer-Policy: Controls referrer information leakage
"""

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Content Security Policy
# Nonce-based CSP is used when available (set by route handlers via get_csp_nonce).
# Fallback CSP with unsafe-inline is used for non-HTML responses or error pages.
DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _build_csp_with_nonce(nonce: str) -> str:
    """Build CSP header with nonce for inline scripts and styles.

    Args:
        nonce: The cryptographic nonce for this request

    Returns:
        CSP header value with nonce replacing unsafe-inline
    """
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

# X-Frame-Options: Prevent the page from being embedded in frames
DEFAULT_X_FRAME_OPTIONS = "DENY"

# X-Content-Type-Options: Prevent MIME sniffing
DEFAULT_X_CONTENT_TYPE_OPTIONS = "nosniff"

# Strict-Transport-Security: Enforce HTTPS for 1 year
# Only set if the connection is HTTPS
DEFAULT_HSTS = "max-age=31536000; includeSubDomains"

# Referrer-Policy: Control referrer information
DEFAULT_REFERRER_POLICY = "strict-origin-when-cross-origin"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all HTTP responses.

    Usage:
        app.add_middleware(SecurityHeadersMiddleware)

    Optional custom configuration:
        app.add_middleware(
            SecurityHeadersMiddleware,
            csp="custom-csp-policy",
            hsts="max-age=63072000"
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        csp: str | None = None,
        x_frame_options: str | None = None,
        x_content_type_options: str | None = None,
        hsts: str | None = None,
        referrer_policy: str | None = None,
    ):
        """Initialize the middleware.

        Args:
            app: The ASGI application
            csp: Custom Content-Security-Policy value (optional)
            x_frame_options: Custom X-Frame-Options value (optional)
            x_content_type_options: Custom X-Content-Type-Options value (optional)
            hsts: Custom Strict-Transport-Security value (optional)
            referrer_policy: Custom Referrer-Policy value (optional)
        """
        super().__init__(app)
        self.csp = csp or DEFAULT_CSP
        self.x_frame_options = x_frame_options or DEFAULT_X_FRAME_OPTIONS
        self.x_content_type_options = x_content_type_options or DEFAULT_X_CONTENT_TYPE_OPTIONS
        self.hsts = hsts or DEFAULT_HSTS
        self.referrer_policy = referrer_policy or DEFAULT_REFERRER_POLICY

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Process the request and add security headers to the response."""
        # Skip non-HTTP requests
        if request.scope["type"] != "http":
            return await call_next(request)

        # Call the next middleware/route handler
        response: Response = await call_next(request)

        # Use nonce-based CSP if a nonce was generated for this request
        # (set by route handlers via get_csp_nonce)
        nonce = getattr(request.state, "csp_nonce", None)
        if nonce:
            csp = _build_csp_with_nonce(nonce)
        else:
            csp = self.csp

        # Add security headers to the response
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Frame-Options"] = self.x_frame_options
        response.headers["X-Content-Type-Options"] = self.x_content_type_options
        response.headers["Referrer-Policy"] = self.referrer_policy

        # Only add HSTS header if the connection is HTTPS
        # In development (HTTP), we skip HSTS to avoid browser warnings
        scheme = request.url.scheme
        if scheme == "https":
            response.headers["Strict-Transport-Security"] = self.hsts

        return response
