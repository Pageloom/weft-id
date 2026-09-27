"""CSRF protection middleware for web forms.

This middleware implements the Synchronizer Token Pattern:
1. A CSRF token is generated and stored in the session
2. Forms must include the token as a hidden field
3. POST requests are validated against the session token

API routes are exempt (they use Bearer tokens for authentication).
SAML ACS is exempt (receives POST from external IdPs).
"""

import logging
import secrets
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Routes that are exempt from CSRF protection
# - API routes use Bearer token authentication
# - Inbound SCIM is called by external IdPs with a per-connection bearer token
# - SAML ACS receives POSTs from external Identity Providers
# - OAuth2 token endpoint is called by OAuth clients
CSRF_EXEMPT_PATHS = [
    "/api/",  # All API routes (prefix match)
    "/scim/",  # Inbound SCIM receiver (bearer token from the IdP, prefix match)
    "/saml/acs",  # SAML Assertion Consumer Service
    "/saml/slo",  # SAML SP SLO endpoint (receives POST from external IdPs)
    "/saml/idp/sso",  # SAML IdP SSO endpoint (receives POST from external SPs)
    "/saml/idp/slo",  # SAML IdP SLO endpoint (receives POST from external SPs)
    "/oauth2/token",  # OAuth2 token endpoint
]

# Exact-path exemptions (no prefix match). The OAuth2 authorization endpoint
# must accept a cross-site POST carrying the same parameters as the GET form
# (OpenID Connect Core 1.0, section 3.1.2.1); the request is validated against
# the client's registration, not the session. Its sibling
# ``/oauth2/authorize/decision`` (the consent form) is NOT exempt, which is why
# this is an exact match rather than a prefix. The OIDC userinfo endpoint
# accepts POST (OpenID Connect Core 1.0, section 5.3.1) and authenticates only
# by a bearer access token, never by the session cookie.
CSRF_EXEMPT_EXACT_PATHS = frozenset({"/oauth2/authorize", "/userinfo"})

# HTTP methods that require CSRF validation
CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Session key for storing CSRF token
CSRF_SESSION_KEY = "_csrf_token"

# Form field name for CSRF token
CSRF_FORM_FIELD = "csrf_token"

# Header name for CSRF token (for AJAX requests)
CSRF_HEADER_NAME = "X-CSRF-Token"


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def get_csrf_token(request: Request) -> str:
    """Get or create CSRF token from session.

    This function ensures a CSRF token exists in the session.
    If not present, a new one is generated and stored.
    """
    session = request.session
    if CSRF_SESSION_KEY not in session:
        session[CSRF_SESSION_KEY] = generate_csrf_token()
    token: str = session[CSRF_SESSION_KEY]
    return token


def make_csrf_token_func(request: Request) -> Callable[[], str]:
    """Create a csrf_token() function bound to a request.

    Use this in template contexts that don't use get_template_context():
        context = {"csrf_token": make_csrf_token_func(request), ...}

    Then in templates:
        {{ csrf_token() }}
    """

    def csrf_token() -> str:
        return get_csrf_token(request)

    return csrf_token


def _is_exempt(path: str) -> bool:
    """Check if a path is exempt from CSRF protection."""
    if path in CSRF_EXEMPT_EXACT_PATHS:
        return True
    for exempt_path in CSRF_EXEMPT_PATHS:
        if path.startswith(exempt_path):
            return True
    return False


class CSRFMiddleware(BaseHTTPMiddleware):
    """Middleware to validate CSRF tokens on state-changing requests.

    Usage:
        app.add_middleware(CSRFMiddleware)

    Templates should include:
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

    AJAX requests should include the header:
        X-CSRF-Token: <token value>
    """

    def __init__(self, app: ASGIApp, error_handler: Callable[[Request], Response] | None = None):
        """Initialize the middleware.

        Args:
            app: The ASGI application
            error_handler: Optional custom handler for CSRF failures.
                          If not provided, returns a 403 Forbidden response.
        """
        super().__init__(app)
        self.error_handler = error_handler

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Process the request and validate CSRF token if needed."""
        # Skip non-HTTP requests
        if request.scope["type"] != "http":
            response: Response = await call_next(request)
            return response

        # Skip safe methods (GET, HEAD, OPTIONS)
        if request.method not in CSRF_PROTECTED_METHODS:
            response = await call_next(request)
            return response

        # Skip exempt paths
        if _is_exempt(request.url.path):
            response = await call_next(request)
            return response

        # Validate CSRF token
        if not await self._validate_csrf_token(request):
            return self._csrf_failure_response(request)

        response = await call_next(request)
        return response

    async def _validate_csrf_token(self, request: Request) -> bool:
        """Validate the CSRF token from request against session.

        Returns True if valid, False otherwise.
        """
        # Fail closed if there is no session in scope. The only way to get
        # here is a middleware misordering (this middleware registered after,
        # and therefore running outside of, the session middleware) or the
        # session middleware missing altogether. Either way the token cannot
        # be checked, and silently allowing the request would disable CSRF
        # protection for the whole application. This exact fail-open bug
        # shipped for eleven months; see .claude/ISSUES_ARCHIVE.md.
        if "session" not in request.scope:
            logger.error(
                "CSRF validation impossible: no session in request scope. "
                "CSRFMiddleware must be registered before (inside) the session "
                "middleware in app/main.py. Rejecting %s %s.",
                request.method,
                request.url.path,
            )
            return False

        # Read the session from the ASGI scope rather than through the
        # ``Request.session`` property. They are the same dict in production;
        # reading the scope keeps this layer bound to the real signed cookie
        # even when a test replaces ``Request.session`` for a route handler.
        session_token = request.scope["session"].get(CSRF_SESSION_KEY)
        if not session_token:
            return False

        # Try to get token from form data
        request_token = None

        # Check header first (for AJAX requests)
        request_token = request.headers.get(CSRF_HEADER_NAME)

        # Check form data if not in header
        if not request_token:
            content_type = request.headers.get("content-type", "")
            if (
                "application/x-www-form-urlencoded" in content_type
                or "multipart/form-data" in content_type
            ):
                try:
                    # Read the raw body BEFORE parsing the form. Starlette's
                    # BaseHTTPMiddleware replays the body to the downstream
                    # app only if it was read via ``request.body()``;
                    # ``request.form()`` alone consumes the stream and the
                    # route handler then sees an empty body (every Form()
                    # parameter missing -> 422). ``form()`` reads from the
                    # cached body once it exists, so parsing happens once.
                    await request.body()
                    # Context manager: closes any UploadFile temp files this
                    # parse created. The handler re-parses from the replayed
                    # body and gets its own file objects.
                    async with request.form() as form:
                        form_token = form.get(CSRF_FORM_FIELD)
                        # CSRF token is always a string, not an UploadFile
                        if isinstance(form_token, str):
                            request_token = form_token
                except Exception:
                    return False

        if not request_token:
            return False

        # Constant-time comparison to prevent timing attacks
        return secrets.compare_digest(session_token, str(request_token))

    def _csrf_failure_response(self, request: Request) -> Response:
        """Return the response for CSRF validation failure."""
        if self.error_handler:
            return self.error_handler(request)

        # Check if request expects HTML or JSON
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            from starlette.responses import JSONResponse

            return JSONResponse(
                {"detail": "CSRF token validation failed"},
                status_code=403,
            )

        # HTML response
        from starlette.responses import HTMLResponse

        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>403 Forbidden</title></head>
            <body>
                <h1>403 Forbidden</h1>
                <p>CSRF token validation failed. Please go back and try again.</p>
                <p><a href="javascript:history.back()">Go Back</a></p>
            </body>
            </html>
            """,
            status_code=403,
        )
