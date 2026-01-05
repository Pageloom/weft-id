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
from middleware.session import DynamicSessionMiddleware  # noqa: E402
from routers import account as account_router  # noqa: E402
from routers import admin as admin_router  # noqa: E402
from routers import auth, mfa, oauth2, saml, tenants, users  # noqa: E402
from routers import settings as settings_router  # noqa: E402
from routers.api.v1 import events as events_api  # noqa: E402
from routers.api.v1 import oauth2_clients  # noqa: E402
from routers.api.v1 import reactivation as reactivation_api  # noqa: E402
from routers.api.v1 import saml as saml_api  # noqa: E402
from routers.api.v1 import settings as settings_api  # noqa: E402
from routers.api.v1 import users as users_api  # noqa: E402

logger = logging.getLogger(__name__)

# Security warnings for dangerous settings
if settings.BYPASS_OTP:
    logger.warning("BYPASS_OTP is enabled. Any 6-digit code will pass MFA verification.")
    logger.warning("This should ONLY be used in development or controlled on-prem environments.")

app = FastAPI(
    title="Loom Identity Platform API",
    version="1.0.0",
    description="Multi-tenant identity platform with OAuth2 and RESTful API",
    openapi_url="/openapi.json",
    docs_url="/docs",
)

# Add session middleware with dynamic per-tenant session configuration
app.add_middleware(DynamicSessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)


@app.exception_handler(RedirectError)
async def redirect_error_handler(request: Request, exc: RedirectError):
    """Handle RedirectError by returning a RedirectResponse."""
    return RedirectResponse(url=exc.url, status_code=exc.status_code)


# Mount static files (if directory exists)
static_dir = Path("static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers - Web UI (HTML)
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(account_router.router)
app.include_router(admin_router.router)
app.include_router(settings_router.router)
app.include_router(tenants.router)
app.include_router(users.router)

# Include OAuth2 and SAML routers
app.include_router(oauth2.router)
app.include_router(saml.router)

# Include API routers (JSON)
app.include_router(events_api.router)
app.include_router(oauth2_clients.router)
app.include_router(reactivation_api.router)
app.include_router(saml_api.router)
app.include_router(settings_api.router)
app.include_router(users_api.router)


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
