from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import settings
from middleware.session import DynamicSessionMiddleware
from routers import auth, mfa, tenants, users
from routers import account as account_router
from routers import settings as settings_router

app = FastAPI(title="Loom")

# Add session middleware with dynamic per-tenant session configuration
app.add_middleware(DynamicSessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)

# Mount static files (if directory exists)
static_dir = Path("static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(account_router.router)
app.include_router(settings_router.router)
app.include_router(tenants.router)
app.include_router(users.router)
