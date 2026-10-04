"""Admin endpoints for OIDC upstream (relying-party) connection management.

Mirrors ``routers.saml.admin.providers`` for the consuming direction of OIDC:
list, create/edit form with the vendor preset picker, detail tabs (details /
danger), and a real test-connection action that runs discovery. The
claim-mapping tab also carries the group claim settings.

The client secret is write-only: it is accepted on the create form but never
rendered back into any template.
"""

import logging
import re
from typing import Annotated
from urllib.parse import quote

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
from schemas.oidc_upstream import (
    MAX_APPLE_PRIVATE_KEY_LENGTH,
    PROVIDER_TYPES,
    OIDCConnectionCreate,
    OIDCConnectionUpdate,
)
from services import oidc_upstream as oidc_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.redirects import safe_redirect
from utils.template_context import get_template_context
from utils.templates import templates
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter()

CONNECTION_LIST_URL = "/identity-providers/oidc"

# The page keys used for the per-connection detail tabs (registered in pages.py).
_PAGE_CONNECTION = "/identity-providers/oidc/connection"
_PAGE_DETAILS = "/identity-providers/oidc/connection/details"
_PAGE_CLAIM_MAPPING = "/identity-providers/oidc/connection/claim-mapping"
_PAGE_DANGER = "/identity-providers/oidc/connection/danger"


def _load_connection_common(request: Request, tenant_id: str, user: dict, connection_id: str):
    """Load a connection config for the tab bar. Returns (connection, requesting_user)."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    connection = oidc_service.get_connection(
        requesting_user, connection_id, tenant_base_url(request)
    )
    return connection, requesting_user


def _parse_org_list(value: str) -> list[str]:
    """Split a free-text organization list (commas, spaces or new lines)."""
    return [org for org in re.split(r"[\s,]+", value) if org]


def _preset_defaults() -> dict[str, dict]:
    """Return the preset defaults for the form's vendor picker."""
    return {
        provider_type: oidc_service.get_preset_defaults(provider_type)
        for provider_type in PROVIDER_TYPES
    }


# =============================================================================
# List, New, Create
# =============================================================================


@router.get(
    "/identity-providers/oidc",
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
    "/identity-providers/oidc/new",
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
    "/identity-providers/oidc/new",
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
    authorization_endpoint: Annotated[str, Form(max_length=2048)] = "",
    token_endpoint: Annotated[str, Form(max_length=2048)] = "",
    userinfo_endpoint: Annotated[str, Form(max_length=2048)] = "",
    jwks_uri: Annotated[str, Form(max_length=2048)] = "",
    end_session_endpoint: Annotated[str, Form(max_length=2048)] = "",
    client_id: Annotated[str, Form(max_length=255)] = "",
    client_secret: Annotated[str, Form(max_length=3000)] = "",
    scopes: Annotated[str, Form(max_length=500)] = "",
    correlation_claim: Annotated[str, Form(max_length=50)] = "",
    hosted_domain: Annotated[str, Form(max_length=253)] = "",
    entra_tenant_id: Annotated[str, Form(max_length=100)] = "",
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
    allow_email_linking: Annotated[bool, Form()] = False,
    show_on_login: Annotated[bool, Form()] = False,
    github_allowed_orgs: Annotated[str, Form(max_length=4100)] = "",
    apple_team_id: Annotated[str, Form(max_length=50)] = "",
    apple_key_id: Annotated[str, Form(max_length=50)] = "",
    apple_private_key: Annotated[str, Form(max_length=MAX_APPLE_PRIVATE_KEY_LENGTH)] = "",
):
    """Create a new OIDC upstream connection from the admin form."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = tenant_base_url(request)

    # The service layer composes the issuer/discovery URL and applies preset
    # defaults (scopes, correlation claim) server-side, so the form only needs
    # to pass through what the admin typed. Empty strings become None so the
    # preset defaults apply.
    try:
        data = OIDCConnectionCreate(
            name=name,
            provider_type=provider_type,
            issuer=issuer.strip() or None,
            discovery_url=discovery_url.strip() or None,
            authorization_endpoint=authorization_endpoint.strip() or None,
            token_endpoint=token_endpoint.strip() or None,
            userinfo_endpoint=userinfo_endpoint.strip() or None,
            jwks_uri=jwks_uri.strip() or None,
            end_session_endpoint=end_session_endpoint.strip() or None,
            client_id=client_id.strip() or None,
            client_secret=client_secret or None,
            scopes=scopes.strip() or None,
            correlation_claim=correlation_claim.strip() or None,
            hosted_domain=hosted_domain.strip() or None,
            entra_tenant_id=entra_tenant_id.strip() or None,
            require_platform_mfa=require_platform_mfa,
            jit_provisioning=jit_provisioning,
            allow_email_linking=allow_email_linking,
            show_on_login=show_on_login,
            github_allowed_orgs=_parse_org_list(github_allowed_orgs) or None,
            apple_team_id=apple_team_id.strip() or None,
            apple_key_id=apple_key_id.strip() or None,
            apple_private_key=apple_private_key.strip() or None,
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
    "/identity-providers/oidc/{connection_id}",
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
    "/identity-providers/oidc/{connection_id}/details",
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
    "/identity-providers/oidc/{connection_id}/claim-mapping",
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
    "/identity-providers/oidc/{connection_id}/edit-claim-mapping",
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


@router.post(
    "/identity-providers/oidc/{connection_id}/edit-group-claim",
    dependencies=[Depends(require_super_admin)],
)
def edit_group_claim(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
    group_claim_source: Annotated[str, Form(max_length=255)] = "",
    group_claim_name_key: Annotated[str, Form(max_length=100)] = "",
):
    """Update the group claim settings (claim-mapping tab).

    An empty claim name disables group sync; an empty name key falls back
    to ``name``. Both are stored as NULL when blank.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.update_connection(
            requesting_user,
            connection_id,
            OIDCConnectionUpdate(
                group_claim_source=group_claim_source,
                group_claim_name_key=group_claim_name_key,
            ),
            tenant_base_url(request),
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/claim-mapping?error={str(e)}")

    return safe_redirect(
        f"{CONNECTION_LIST_URL}/{connection_id}/claim-mapping?success=group_claim_updated"
    )


@router.get(
    "/identity-providers/oidc/{connection_id}/danger",
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

    # Linked users (for the per-user disconnect surface). A listing failure
    # must not silently pass: surface it in the logs so a recurring outage is
    # visible to operators rather than rendering an empty (misleading) table.
    linked_users: list[dict] = []
    try:
        linked_users = oidc_service.list_connection_linked_users(requesting_user, connection_id)
    except ServiceError as exc:
        logger.warning(
            "Failed to list linked users for OIDC connection %s: %s",
            connection_id,
            exc,
        )

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
    "/identity-providers/oidc/{connection_id}/edit",
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
    "/identity-providers/oidc/{connection_id}/edit-endpoints",
    dependencies=[Depends(require_super_admin)],
)
def edit_connection_endpoints(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
    authorization_endpoint: Annotated[str, Form(max_length=2048)] = "",
    token_endpoint: Annotated[str, Form(max_length=2048)] = "",
    userinfo_endpoint: Annotated[str, Form(max_length=2048)] = "",
    jwks_uri: Annotated[str, Form(max_length=2048)] = "",
    end_session_endpoint: Annotated[str, Form(max_length=2048)] = "",
):
    """Set the endpoints by hand for an IdP that publishes no discovery.

    Mirrors the ``PATCH /api/v1/oidc-upstream/connections/{id}`` semantics: a
    blank field leaves the stored value untouched. A later successful Test
    Connection overwrites them with the discovered values.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    data = OIDCConnectionUpdate(
        authorization_endpoint=authorization_endpoint.strip() or None,
        token_endpoint=token_endpoint.strip() or None,
        userinfo_endpoint=userinfo_endpoint.strip() or None,
        jwks_uri=jwks_uri.strip() or None,
        end_session_endpoint=end_session_endpoint.strip() or None,
    )

    try:
        oidc_service.update_connection(
            requesting_user, connection_id, data, tenant_base_url(request)
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success=endpoints_updated")


@router.post(
    "/identity-providers/oidc/{connection_id}/edit-settings",
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
    sign_out_at_idp: Annotated[bool, Form()] = False,
    show_on_login: Annotated[bool, Form()] = False,
):
    """Update connection settings (enabled, default, MFA, JIT, email linking,
    sign-out, login page button)."""
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
                sign_out_at_idp=sign_out_at_idp,
                show_on_login=show_on_login,
            ),
            base_url,
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success=settings_updated")


@router.post(
    "/identity-providers/oidc/{connection_id}/edit-apple-key",
    dependencies=[Depends(require_super_admin)],
)
def edit_apple_key(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
    apple_team_id: Annotated[str, Form(max_length=50)] = "",
    apple_key_id: Annotated[str, Form(max_length=50)] = "",
    apple_private_key: Annotated[str, Form(max_length=MAX_APPLE_PRIVATE_KEY_LENGTH)] = "",
):
    """Set the Apple team ID, key ID and private key (blank leaves a value as is)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        data = OIDCConnectionUpdate(
            apple_team_id=apple_team_id.strip() or None,
            apple_key_id=apple_key_id.strip() or None,
            apple_private_key=apple_private_key.strip() or None,
        )
    except PydanticValidationError:
        message = quote("Team ID and key ID are 10 upper-case letters and digits.")
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?error={message}")

    try:
        oidc_service.update_connection(
            requesting_user, connection_id, data, tenant_base_url(request)
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(
            f"{CONNECTION_LIST_URL}/{connection_id}/details?error={quote(e.message)}"
        )

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success=apple_key_updated")


@router.post(
    "/identity-providers/oidc/{connection_id}/edit-github-orgs",
    dependencies=[Depends(require_super_admin)],
)
def edit_github_allowed_orgs(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
    github_allowed_orgs: Annotated[str, Form(max_length=4100)] = "",
):
    """Set the GitHub organizations a user must belong to (blank clears it)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        data = OIDCConnectionUpdate(github_allowed_orgs=_parse_org_list(github_allowed_orgs))
    except PydanticValidationError:
        message = quote(
            "Organization names may hold only letters, digits and hyphens (up to 39 "
            "characters), and at most 100 organizations."
        )
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?error={message}")

    try:
        oidc_service.update_connection(
            requesting_user, connection_id, data, tenant_base_url(request)
        )
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?success=orgs_updated")


@router.post(
    "/identity-providers/oidc/{connection_id}/toggle",
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
    "/identity-providers/oidc/{connection_id}/set-default",
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
    "/identity-providers/oidc/{connection_id}/delete",
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
    "/identity-providers/oidc/{connection_id}/unlink-user/{user_id}",
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
    "/identity-providers/oidc/{connection_id}/test-connection",
    dependencies=[Depends(require_super_admin)],
)
def test_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    connection_id: str,
):
    """Run real discovery and fetch the key set, then report the result.

    This is not a placeholder: it fetches the IdP's discovery document through
    the SSRF guard, validates the issuer, persists the discovered endpoints,
    and fetches the JWKS they advertise. On success the details tab shows the
    discovered endpoints; on failure the reason is surfaced.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.test_connection(requesting_user, connection_id, tenant_base_url(request))
    except NotFoundError:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error=not_found")
    except ValidationError as e:
        return safe_redirect(
            f"{CONNECTION_LIST_URL}/{connection_id}/details?test=error"
            f"&test_detail={quote(e.message)}"
        )
    except ServiceError as e:
        return safe_redirect(f"{CONNECTION_LIST_URL}?error={str(e)}")

    return safe_redirect(f"{CONNECTION_LIST_URL}/{connection_id}/details?test=success")
