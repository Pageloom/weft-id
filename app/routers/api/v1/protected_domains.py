"""REST API endpoints for protected-domain (forward-auth) management.

A protected domain is a DNS/web domain a tenant registers so WeftID can act as
its forward-auth authority. Ownership is proven via a DNS-TXT challenge before the
domain is admitted for TLS issuance or per-domain cookies.
"""

from typing import Annotated

from api_dependencies import require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, status
from schemas.protected_domains import (
    ProtectedDomain,
    ProtectedDomainCreate,
    ProtectedDomainList,
    ProtectedDomainVerifyResult,
)
from services import protected_domains as protected_domains_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/protected-domains", tags=["Protected Domains"])


@router.get("", response_model=ProtectedDomainList)
def list_protected_domains(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """List all protected domains for the tenant.

    Requires super_admin role.

    Each item includes: id, domain, portal_host, verification_status
    (pending | verified | failed), verification_token (null once verified),
    verification_record_name, verification_record_value, verified_at, enabled,
    created_at, created_by_name.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return protected_domains_service.list_protected_domains(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("", response_model=ProtectedDomain, status_code=status.HTTP_201_CREATED)
def register_protected_domain(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    data: ProtectedDomainCreate,
):
    """Register a domain to protect with forward auth.

    Requires super_admin role.

    Request body:
    - domain (str, required): the DNS domain to protect, e.g. "acme-corp.com".
    - portal_host (str, required): the WeftID portal host under that domain,
      e.g. "auth.acme-corp.com". Must be the domain itself or a subdomain of it.

    Returns the created domain in 'pending' state with the DNS-TXT challenge
    (verification_record_name + verification_record_value) to publish. Call the
    verify endpoint after publishing the record.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return protected_domains_service.register_protected_domain(requesting_user, data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{domain_id}", response_model=ProtectedDomain)
def get_protected_domain(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    domain_id: str,
):
    """Get a single protected domain by ID.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return protected_domains_service.get_protected_domain(requesting_user, domain_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{domain_id}/verify", response_model=ProtectedDomainVerifyResult)
def verify_protected_domain(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    domain_id: str,
):
    """Re-run the DNS-TXT ownership verification for a protected domain.

    Requires super_admin role.

    Resolves the challenge TXT record at verification_record_name. On a match the
    domain flips to 'verified' and is admitted for TLS + per-domain cookies. On a
    miss it becomes 'failed' and can be retried after DNS propagates. This action
    is idempotent and re-runnable.

    Returns: verified (bool), status (pending | verified | failed), message.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return protected_domains_service.verify_protected_domain(requesting_user, domain_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_protected_domain(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    domain_id: str,
):
    """Delete a protected domain.

    Requires super_admin role. Cascades to its proxy apps and their grants.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        protected_domains_service.delete_protected_domain(requesting_user, domain_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
