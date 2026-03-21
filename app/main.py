import logging
import os
import time
from pathlib import Path

# Force server timezone to UTC for consistent datetime handling
# This must happen before any other imports that might use datetime
os.environ["TZ"] = "UTC"
time.tzset()

import settings  # noqa: E402
from dependencies import RedirectError  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.openapi.utils import get_openapi  # noqa: E402
from fastapi.responses import RedirectResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from middleware.csrf import CSRFMiddleware  # noqa: E402
from middleware.request_context import RequestContextMiddleware  # noqa: E402
from middleware.security_headers import SecurityHeadersMiddleware  # noqa: E402
from middleware.session import DynamicSessionMiddleware  # noqa: E402
from middleware.tenant_guard import TenantGuardMiddleware  # noqa: E402
from routers import account as account_router  # noqa: E402
from routers import admin as admin_router  # noqa: E402
from routers import auth, mfa, oauth2, saml, tenants, users  # noqa: E402
from routers import branding as branding_router  # noqa: E402
from routers import groups as groups_router  # noqa: E402
from routers import health as health_router  # noqa: E402
from routers import integrations as integrations_router  # noqa: E402
from routers import saml_idp as saml_idp_router  # noqa: E402
from routers import settings as settings_router  # noqa: E402
from routers import settings_branding as settings_branding_router  # noqa: E402
from routers.api.v1 import branding as branding_api  # noqa: E402
from routers.api.v1 import events as events_api  # noqa: E402
from routers.api.v1 import exports as exports_api  # noqa: E402
from routers.api.v1 import groups as groups_api  # noqa: E402
from routers.api.v1 import jobs as jobs_api  # noqa: E402
from routers.api.v1 import oauth2_clients  # noqa: E402
from routers.api.v1 import reactivation as reactivation_api  # noqa: E402
from routers.api.v1 import saml as saml_api  # noqa: E402
from routers.api.v1 import service_providers as service_providers_api  # noqa: E402
from routers.api.v1 import settings as settings_api  # noqa: E402
from routers.api.v1 import users as users_api  # noqa: E402
from utils.crypto import derive_session_key  # noqa: E402

logger = logging.getLogger(__name__)

# Validate production settings (secrets and dangerous flags)
settings.validate_production_settings()

# Log warning for BYPASS_OTP even in dev mode (helpful reminder)
if settings.BYPASS_OTP:
    logger.warning("BYPASS_OTP is enabled. Any 6-digit code will pass OTP verification.")

app = FastAPI(
    title="Loom Identity Platform API",
    version="1.0.0",
    description="Multi-tenant identity platform with OAuth2 and RESTful API",
    openapi_url="/openapi.json" if settings.ENABLE_OPENAPI_DOCS else None,
    docs_url="/api/docs" if settings.ENABLE_OPENAPI_DOCS else None,
    redoc_url="/api/redoc" if settings.ENABLE_OPENAPI_DOCS else None,
)

# Reject requests without a tenant subdomain (outermost, runs first)
# /healthz is exempt so load balancers can probe without a subdomain
app.add_middleware(TenantGuardMiddleware)

# Add session middleware with dynamic per-tenant session configuration
app.add_middleware(
    DynamicSessionMiddleware,
    secret_key=derive_session_key(),
    https_only=not settings.IS_DEV,
)

# Add CSRF protection middleware (must be after session middleware so it has access to session)
# API routes, SAML ACS, and OAuth2 token endpoint are exempt
app.add_middleware(CSRFMiddleware)

# Add security headers middleware
# Adds HTTP security headers to all responses
app.add_middleware(SecurityHeadersMiddleware)

# Add request context middleware (populates context for event logging)
# Extracts IP, user agent, device, session hash into contextvar
app.add_middleware(RequestContextMiddleware)


@app.exception_handler(RedirectError)
async def redirect_error_handler(request: Request, exc: RedirectError):
    """Handle RedirectError by returning a RedirectResponse."""
    return RedirectResponse(url=exc.url, status_code=exc.status_code)


# Mount static files (if directory exists)
static_dir = Path("static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Mount documentation site (built by MkDocs)
# Local dev: site/ is next to app/. Docker: site/ is at /site.
for _docs_candidate in [Path(__file__).resolve().parent.parent / "site", Path("/site")]:
    if _docs_candidate.is_dir():
        app.mount("/docs", StaticFiles(directory=str(_docs_candidate), html=True), name="docs")
        break

# Infrastructure routes (no tenant context required)
app.include_router(health_router.router)

# Include routers - Web UI (HTML)
app.include_router(branding_router.router)
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(account_router.router)
app.include_router(admin_router.router)
app.include_router(groups_router.router)
app.include_router(integrations_router.router)
app.include_router(saml_idp_router.router)
app.include_router(settings_router.router)
app.include_router(settings_branding_router.router)
app.include_router(tenants.router)
app.include_router(users.router)

# Include OAuth2 and SAML routers
app.include_router(oauth2.router)
app.include_router(saml.router)

# Include API routers (JSON)
app.include_router(branding_api.router)
app.include_router(events_api.router)
app.include_router(exports_api.router)
app.include_router(groups_api.router)
app.include_router(jobs_api.router)
app.include_router(oauth2_clients.router)
app.include_router(reactivation_api.router)
app.include_router(saml_api.router)
app.include_router(service_providers_api.router)
app.include_router(service_providers_api.my_apps_router)
app.include_router(settings_api.router)
app.include_router(users_api.router)

# Dev-only router (instant login for E2E tests)
if settings.IS_DEV:
    from routers import dev as dev_router  # noqa: E402

    app.include_router(dev_router.router)


# Configure OpenAPI with OAuth2 security schemes
def custom_openapi():
    """Customize OpenAPI schema with OAuth2 security schemes."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Loom Identity Platform API",
        version="1.0.0",
        description="Multi-tenant identity platform with OAuth2 and RESTful API",
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerToken": {
            "type": "http",
            "scheme": "bearer",
            "description": "OAuth2 access token (Bearer token)",
        },
        "SessionCookie": {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
            "description": "Session cookie from web login",
        },
    }

    # Apply security to all API endpoints
    # Security is an OR - either Bearer token OR session cookie
    api_security = [{"BearerToken": []}, {"SessionCookie": []}]

    for path, path_item in openapi_schema.get("paths", {}).items():
        if path.startswith("/api/"):
            for method in path_item.values():
                if isinstance(method, dict):
                    method["security"] = api_security

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore[method-assign]
