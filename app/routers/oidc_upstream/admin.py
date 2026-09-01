"""Admin endpoints for OIDC upstream (relying-party) connection management.

Mirrors ``routers.saml.admin.providers`` for the consuming direction of OIDC:
list, create/edit form with the vendor preset picker, detail tabs (details /
danger), and a real test-connection action that runs discovery. The
claim-mapping tab arrives in Iteration 5.

The client secret is write-only: it is accepted on the create form but never
rendered back into any template.
"""

import logging
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import has_page_access
from pydantic import ValidationError as PydanticValidationError
from schemas.oidc_upstream import OIDCConnectionCreate, OIDCConnectionUpdate
from services import oidc_upstream as oidc_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.redirects import safe_redirect
from utils.template_context import get_template_context
from utils.templates import templates
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter()

CONNECTION_LIST_URL = "/admin/settings/oidc-identity-providers"

# The page keys used for the per-connection detail tabs (registered in pages.py).
_PAGE_CONNECTION = "/admin/settings/oidc-identity-providers/connection"
_PAGE_DETAILS = "/admin/settings/oidc-identity-providers/connection/details"
_PAGE_CLAIM_MAPPING = "/admin/settings/oidc-identity-providers/connection/claim-mapping"
_PAGE_DANGER = "/admin/settings/oidc-identity-providers/connection/danger"


def _load_connection_common(request: Request, tenant_id: str, user: dict, connection_id: str):
    """Load a connection config for the tab bar. Returns (connection, requesting_user)."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    connection = oidc_service.get_connection(
        requesting_user, connection_id, tenant_base_url(request)
    )
    return connection, requesting_user


def _preset_defaults() -> dict[str, dict]:
    """Return the preset defaults for the form's vendor picker."""
    return {
        provider_type: oidc_service.get_preset_defaults(provider_type)
        for provider_type in ("generic", "google", "entra")
    }


# =============================================================================
# List, New, Create
# =============================================================================


@router.get(
    "/admin/settings/oidc-identity-providers",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def list_connections(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List OIDC upstream connections for admin management."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        connection_list = oidc_service.list_connections(requesting_user)
    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "oidc_idp_list.html",
            get_template_context(request, tenant_id, connections=[], error=str(e)),
        )

    return templates.TemplateResponse(
        request,
        "oidc_idp_list.html",
        get_template_context(
            request,
            tenant_id,
            connections=connection_list.items,
            success=request.query_params.get("success"),
            error=request.query_params.get("error"),
        ),
    )


@router.get(
    "/admin/settings/oidc-identity-providers/new",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def new_connection_form(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display the form to create a new OIDC upstream connection."""
    return templates.TemplateResponse(
        request,
        "oidc_idp_form.html",
        get_template_context(
            request,
            tenant_id,
            presets=_preset_defaults(),
            error=request.query_params.get("error"),
        ),
    )


@router.post(
    "/admin/settings/oidc-identity-providers/new",
    dependencies=[Depends(require_super_admin)],
)
def create_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: Annotated[str, Form(max_length=120)],
    provider_type: Annotated[str, Form(max_length=50)],
    issuer: Annotated[str, Form(max_length=2048)] = "",
    discovery_url: Annotated[str, Form(max_length=2048)] = "",
    client_id: Annotated[str, Form(max_length=255)] = "",
    client_secret: Annotated[str, Form(max_length=3000)] = "",
    scopes: Annotated[str, Form(max_length=500)] = "",
    correlation_claim: Annotated[str, Form(max_length=50)] = "sub",
    hosted_domain: Annotated[str, Form(max_length=253)] = "",
    entra_tenant_id: Annotated[str, Form(max_length=100)] = "",
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
    allow_email_linking: Annotated[bool, Form()] = False,
):
    """Create a new OIDC upstream connection from the admin form."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = tenant_base_url(request)

    # Compose the issuer for the Entra preset from its tenant id when the
    # admin did not supply an explicit issuer.
    resolved_issuer = issuer.strip()
    if provider_type == "entra" and not resolved_issuer and entra_tenant_id.strip():
        resolved_issuer = oidc_service.compose_entra_authority(entra_tenant_id.strip())

    try:
        data = OIDCConnectionCreate(
            name=name,
            provider_type=provider_type,
            issuer=resolved_issuer,
            discovery_url=discovery_url.strip() or None,
            client_id=client_id.strip() or None,
            client_secret=client_secret or None,
            scopes=scopes.strip() or None,
            correlation_claim=correlation_claim.strip() or "sub",
            hosted_domain=hosted_domain.strip() or None,
            entra_tenant_id=entra_tenant_id.strip() or None,
            require_platform_mfa=require_platform_mfa,
            jit_provisioning=jit_provisioning,
            allow_email_linking=allow_email_linking,
        )
    except PydanticValidationError:
        # A malformed form value (bad provider type, empty issuer, over-length
        # field) fails schema validation. Redirect back with a generic error
        # rather than leaking field names/values or returning a 500.
        return safe_redirect(f"{CONNECTION_LIST_URL}/new?error=invalid_input")

    try:
        connection = oidc_service.create_connection(requesting_user, data, base_url)
    except ValidationError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/new?error={e.message}")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/new?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection.id}/details?success=created")


# =============================================================================
# Detail - Redirect + Tab Routes
# =============================================================================


@router.get(
    "/admin/settings/oidc-identity-providers/{connection_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def connection_detail_redirect(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Redirect to the Details tab."""
    if not has_page_access(_PAGE_CONNECTION, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details")


@router.get(
    "/admin/settings/oidc-identity-providers/{connection_id}/details",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def connection_tab_details(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Details tab: endpoints, callback URL, settings, and connection test."""
    if not has_page_access(_PAGE_DETAILS, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        connection, _ = _load_connection_common(request, tenant_id, user, connection_id)
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as exc:
        logger.warning("Failed to get OIDC connection: %s", exc)
        return safe_redirect(f"{CONNECTION_LIST_URL}?error={exc.message}")

    context = get_template_context(
        request,
        tenant_id,
        connection=connection,
        active_tab="details",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
        test=request.query_params.get("test"),
        test_detail=request.query_params.get("test_detail"),
    )
    return templates.TemplateResponse(request, "oidc_idp_tab_details.html", context)


@router.get(
    "/admin/settings/oidc-identity-providers/{connection_id}/claim-mapping",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def connection_tab_claim_mapping(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Claim-mapping tab: map OIDC claims to WeftID attributes."""
    if not has_page_access(_PAGE_CLAIM_MAPPING, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        connection, requesting_user = _load_connection_common(
            request, tenant_id, user, connection_id
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as exc:
        logger.warning("Failed to get OIDC connection: %s", exc)
        return safe_redirect(f"{CONNECTION_LIST_URL}?error={exc.message}")

    # Surface enabled tenant attributes alongside the fixed rows, grouped by
    # category, mirroring the SAML attributes tab.
    from constants.user_attributes import CATEGORIES, STANDARD_ATTRIBUTES
    from services import settings as settings_service

    try:
        config_rows = settings_service.list_tenant_attribute_config(requesting_user)
    except ServiceError:
        config_rows = []
    enabled_keys = {row["attribute_key"] for row in config_rows if row.get("enabled")}

    enabled_attribute_groups: list[dict] = []
    for category in CATEGORIES:
        category_attrs = [
            {
                "key": attr.key,
                "default_friendly_name": attr.default_friendly_name,
                "form_field_name": f"attr_{attr.key}",
            }
            for attr in STANDARD_ATTRIBUTES
            if attr.category == category and attr.key in enabled_keys
        ]
        if category_attrs:
            enabled_attribute_groups.append({"category": category, "attributes": category_attrs})

    context = get_template_context(
        request,
        tenant_id,
        connection=connection,
        enabled_attribute_groups=enabled_attribute_groups,
        active_tab="claim-mapping",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "oidc_idp_tab_claim_mapping.html", context)


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/edit-claim-mapping",
    dependencies=[Depends(require_super_admin)],
)
async def edit_claim_mapping(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Update a connection's claim mapping.

    Accepts the three fixed keys (email/first_name/last_name) plus one
    ``attr_<registry_key>`` form field per standard attribute. Empty / missing
    values fall back to the registry's friendly default so saving does not
    silently drop rows.
    """
    from constants.user_attributes import STANDARD_ATTRIBUTES

    requesting_user = build_requesting_user(user, tenant_id, request)
    form = await request.form()

    def _value(field: str, default: str | None = None) -> str | None:
        v = form.get(field)
        if v is None:
            return default
        if not isinstance(v, str):
            return default
        v = v.strip()
        if len(v) > 255:
            v = v[:255]
        return v if v else default

    claim_mapping: dict[str, str] = {
        "email": _value("attr_email", "email") or "email",
        "first_name": _value("attr_first_name", "given_name") or "given_name",
        "last_name": _value("attr_last_name", "family_name") or "family_name",
    }
    for attr in STANDARD_ATTRIBUTES:
        field_name = f"attr_{attr.key}"
        if field_name in form:
            claim_mapping[attr.key] = (
                _value(field_name, attr.default_friendly_name) or attr.default_friendly_name
            )

    try:
        oidc_service.update_claim_mapping(
            requesting_user,
            connection_id,
            claim_mapping,
            tenant_base_url(request),
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/claim-mapping?error={str(e)}")

    return safe_redirect(
        f"{CONNECTION_LIST_URL}/{connection_id}/claim-mapping?success=claim_mapping_updated"
    )


@router.get(
    "/admin/settings/oidc-identity-providers/{connection_id}/danger",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def connection_tab_danger(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Danger tab: enable/disable, set default, delete."""
    if not has_page_access(_PAGE_DANGER, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        connection, requesting_user = _load_connection_common(
            request, tenant_id, user, connection_id
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as exc:
        logger.warning("Failed to get OIDC connection: %s", exc)
        return safe_redirect(f"{CONNECTION_LIST_URL}?error={exc.message}")

    # Linked users (for the per-user disconnect surface).
    linked_users: list[dict] = []
    try:
        linked_users = oidc_service.list_connection_linked_users(requesting_user, connection_id)
    except ServiceError:
        pass

    context = get_template_context(
        request,
        tenant_id,
        connection=connection,
        linked_users=linked_users,
        active_tab="danger",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "oidc_idp_tab_danger.html", context)


# =============================================================================
# Detail - POST Handlers
# =============================================================================


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/edit",
    dependencies=[Depends(require_super_admin)],
)
def edit_connection_name(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
    name: Annotated[str, Form(max_length=120)],
):
    """Update the connection display name (inline edit from details tab)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.update_connection(
            requesting_user,
            connection_id,
            OIDCConnectionUpdate(name=name),
            tenant_base_url(request),
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success=updated")


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/edit-settings",
    dependencies=[Depends(require_super_admin)],
)
def edit_connection_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
    is_enabled: Annotated[bool, Form()] = False,
    is_default: Annotated[bool, Form()] = False,
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
    allow_email_linking: Annotated[bool, Form()] = False,
):
    """Update connection settings (enabled, default, MFA, JIT, email linking)."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = tenant_base_url(request)

    try:
        connection = oidc_service.get_connection(requesting_user, connection_id, base_url)

        if is_enabled != connection.is_enabled:
            oidc_service.set_connection_enabled(
                requesting_user, connection_id, is_enabled, base_url
            )

        if is_default and not connection.is_default:
            oidc_service.set_connection_default(requesting_user, connection_id, base_url)

        oidc_service.update_connection(
            requesting_user,
            connection_id,
            OIDCConnectionUpdate(
                require_platform_mfa=require_platform_mfa,
                jit_provisioning=jit_provisioning,
                allow_email_linking=allow_email_linking,
            ),
            base_url,
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success=settings_updated")


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/toggle",
    dependencies=[Depends(require_super_admin)],
)
def toggle_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Toggle a connection's enabled status."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = tenant_base_url(request)

    try:
        connection = oidc_service.get_connection(requesting_user, connection_id, base_url)
        oidc_service.set_connection_enabled(
            requesting_user, connection_id, not connection.is_enabled, base_url
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error={str(e)}")

    success = "enabled" if not connection.is_enabled else "disabled"
    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success={success}")


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/set-default",
    dependencies=[Depends(require_super_admin)],
)
def set_default_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Set a connection as the default for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.set_connection_default(
            requesting_user, connection_id, tenant_base_url(request)
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success=set_default")


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/delete",
    dependencies=[Depends(require_super_admin)],
)
def delete_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Delete an OIDC upstream connection."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.delete_connection(requesting_user, connection_id)
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/danger?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}?success=deleted")


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/unlink-user/{user_id}",
    dependencies=[Depends(require_super_admin)],
)
def unlink_user_from_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
    user_id: str,
):
    """Disconnect a user from an OIDC connection (per-user disconnect path)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.unlink_user_from_connection(requesting_user, user_id, connection_id)
    except NotFoundError as exc:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/danger?error={exc.code}")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/danger?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/danger?success=user_unlinked")


@router.post(
    "/admin/settings/oidc-identity-providers/{connection_id}/test-connection",
    dependencies=[Depends(require_super_admin)],
)
def test_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Run real discovery against the connection and report the result.

    This is not a placeholder: it fetches the IdP's discovery document through
    the SSRF guard, validates the issuer, and persists the discovered
    endpoints. On success the details tab shows the discovered endpoints; on
    failure the error is surfaced.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Verify the connection exists before running discovery.
    try:
        oidc_service.get_connection(requesting_user, connection_id, tenant_base_url(request))
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error={str(e)}")

    try:
        oidc_service.run_discovery(tenant_id, connection_id, force=True)
    except oidc_service.DiscoveryError as e:
        return safe_redirect(
            f"{CONNECTION_LIST_URL}/{connection_id}/details?test=error&test_detail={str(e)}"
        )

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?test=success")
