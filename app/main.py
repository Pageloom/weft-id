from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from routers import auth, mfa, settings as settings_router, tenants, users
import settings

app = FastAPI(title='Loom')

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)

# Mount static files
app.mount('/static', StaticFiles(directory='static'), name='static')

# Include routers
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(settings_router.router)
app.include_router(tenants.router)
app.include_router(users.router)
