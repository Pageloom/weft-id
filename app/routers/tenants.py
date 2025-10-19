"""Tenant-related API endpoints."""

from dependencies import get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="", tags=["tenants"])


@router.get("/")
def tenant_root(request: Request, tenant_id: str = Depends(get_tenant_id_from_request)):
    """Root endpoint for tenant requests - redirects based on auth state."""
    user = get_current_user(request, tenant_id)

    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    else:
        return RedirectResponse(url="/login", status_code=303)
