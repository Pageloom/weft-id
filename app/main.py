from pathlib import Path

import settings
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from middleware.session import DynamicSessionMiddleware
from routers import account as account_router
from routers import auth, mfa, oauth2, tenants, users
from routers import settings as settings_router
from routers.api.v1 import oauth2_clients
from routers.api.v1 import users as users_api

app = FastAPI(
    title="Loom Identity Platform API",
    version="1.0.0",
    description="Multi-tenant identity platform with OAuth2 and RESTful API",
    openapi_url="/openapi.json",
    docs_url="/docs",
)

# Add session middleware with dynamic per-tenant session configuration
app.add_middleware(DynamicSessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)

# Mount static files (if directory exists)
static_dir = Path("static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers - Web UI (HTML)
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(account_router.router)
app.include_router(settings_router.router)
app.include_router(tenants.router)
app.include_router(users.router)

# Include OAuth2 router
app.include_router(oauth2.router)

# Include API routers (JSON)
app.include_router(oauth2_clients.router)
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
        "OAuth2AuthorizationCode": {
            "type": "oauth2",
            "flows": {
                "authorizationCode": {
                    "authorizationUrl": "/oauth2/authorize",
                    "tokenUrl": "/oauth2/token",
                    "scopes": {},
                }
            },
        },
        "OAuth2ClientCredentials": {
            "type": "oauth2",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": "/oauth2/token",
                    "scopes": {},
                }
            },
        },
        "SessionCookie": {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
        },
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
