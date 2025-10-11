from fastapi import FastAPI

from routers import tenants

app = FastAPI(title='Loom')

# Include routers
app.include_router(tenants.router)
