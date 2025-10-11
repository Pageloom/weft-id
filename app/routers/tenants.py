"""Tenant-related API endpoints."""

from fastapi import APIRouter, Depends, Request

from dependencies import get_tenant_id_from_request

router = APIRouter(prefix='', tags=['tenants'])


@router.get('/')
def tenant_root(request: Request, tenant_id: str = Depends(get_tenant_id_from_request)):
    """Root endpoint for tenant requests."""
    host = request.headers.get('x-forwarded-host') or request.headers.get('host')
    return {'ok': True, 'host': host, 'tenant_id': tenant_id}
