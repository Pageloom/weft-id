"""REST API endpoints for proxy-app (forward-auth) management.

A proxy app is an HTTP application behind a verified protected domain that WeftID
gates as a forward-auth authority. These endpoints provide full CRUD plus group
grant management. All require super_admin (infrastructure config under the Service
Providers section).
"""

from typing import Annotated

from api_dependencies import require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, status
from schemas.proxy_apps import (
    ProxyApp,
    ProxyAppCreate,
    ProxyAppGrant,
    ProxyAppGrantAdd,
    ProxyAppGrantList,
    ProxyAppList,
    ProxyAppUpdate,
)
from services import proxy_apps as proxy_apps_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/proxy-apps", tags=["Proxy Apps"])


@router.get("", response_model=ProxyAppList)
def list_proxy_apps(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """List all proxy apps for the tenant.

    Requires super_admin role.

    Each item includes: id, protected_domain_id, domain, name, external_url,
    description, public_paths, header_config, available_to_all, enabled,
    created_at, updated_at, created_by_name.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return proxy_apps_service.list_proxy_apps(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("", response_model=ProxyApp, status_code=status.HTTP_201_CREATED)
def create_proxy_app(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    data: ProxyAppCreate,
):
    """Create a proxy app under a verified protected domain.

    Requires super_admin role.

    Request body:
    - protected_domain_id (str, required): ID of a verified protected domain.
    - name (str, required): display name, e.g. "Grafana".
    - external_url (str, required): well-formed https URL of the app whose host is
      under the protected domain, e.g. "https://grafana.acme-corp.com".
    - description (str, optional): free-text description.
    - public_paths (list[str], optional): rooted relative path patterns that bypass
      auth, e.g. ["/health", "/public/*"]. Each must start with "/".
    - header_config (dict[str, bool], optional): which X-Forwarded-* identity headers
      to emit on allow. Keys restricted to: user, email, groups, display_name.
    - available_to_all (bool, optional, default false): if true, every authenticated
      tenant user can access without a group grant.
    - enabled (bool, optional, default true): whether forward auth is enabled.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return proxy_apps_service.create_proxy_app(requesting_user, data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{proxy_app_id}", response_model=ProxyApp)
def get_proxy_app(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    proxy_app_id: str,
):
    """Get a single proxy app by ID.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return proxy_apps_service.get_proxy_app(requesting_user, proxy_app_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.patch("/{proxy_app_id}", response_model=ProxyApp)
def update_proxy_app(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    proxy_app_id: str,
    data: ProxyAppUpdate,
):
    """Update a proxy app's mutable fields (all optional).

    Requires super_admin role.

    Request body (any subset):
    - name (str): display name.
    - external_url (str): well-formed https URL under the protected domain.
    - description (str): free-text description (empty string clears it).
    - public_paths (list[str]): rooted relative path patterns; replaces the list.
    - header_config (dict[str, bool]): X-Forwarded-* emission flags; replaces the map.
      Keys restricted to: user, email, groups, display_name.
    - available_to_all (bool): grant-free access toggle.
    - enabled (bool): whether forward auth is enabled.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return proxy_apps_service.update_proxy_app(requesting_user, proxy_app_id, data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{proxy_app_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_proxy_app(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    proxy_app_id: str,
):
    """Delete a proxy app.

    Requires super_admin role. Cascades to its group grants.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        proxy_apps_service.delete_proxy_app(requesting_user, proxy_app_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{proxy_app_id}/grants", response_model=ProxyAppGrantList)
def list_proxy_app_grants(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    proxy_app_id: str,
):
    """List group grants for a proxy app.

    Requires super_admin role.

    Each grant includes: id, proxy_app_id, group_id, group_name,
    group_description, group_type, assigned_by, assigned_at.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return proxy_apps_service.list_proxy_app_grants(requesting_user, proxy_app_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/{proxy_app_id}/grants",
    response_model=ProxyAppGrant,
    status_code=status.HTTP_201_CREATED,
)
def add_proxy_app_grant(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    proxy_app_id: str,
    data: ProxyAppGrantAdd,
):
    """Grant a group access to a proxy app.

    Requires super_admin role.

    Request body:
    - group_id (str, required): ID of the group to grant access.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return proxy_apps_service.add_proxy_app_grant(requesting_user, proxy_app_id, data.group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{proxy_app_id}/grants/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_proxy_app_grant(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    proxy_app_id: str,
    group_id: str,
):
    """Remove a group grant from a proxy app.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        proxy_apps_service.remove_proxy_app_grant(requesting_user, proxy_app_id, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
