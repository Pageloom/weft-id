"""SAML SSO routes for authentication and IdP management."""

import base64
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from schemas.saml import IdPCreate, IdPUpdate, SAMLTestResult
from services import saml as saml_service
from services import settings as settings_service
from services import users as users_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from settings import IS_DEV
from utils.saml import extract_issuer_from_response
from utils.session import regenerate_session
from utils.template_context import get_template_context

router = APIRouter(tags=["saml"], include_in_schema=False)
templates = Jinja2Templates(directory="templates")


def _get_base_url(request: Request) -> str:
    """Get the base URL for the request (always HTTPS)."""
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"


def _decode_saml_response_for_debug(saml_response: str) -> str | None:
    """Safely decode a base64 SAML response for debug display.

    Returns None if decoding fails.
    """
    try:
        return base64.b64decode(saml_response).decode("utf-8")
    except Exception:
        return None


def _handle_saml_test_response(
    request: Request,
    tenant_id: str,
    saml_response: str,
    relay_state: str,
) -> Response:
    """
    Handle SAML response for connection testing (no session/provisioning).

    Args:
        request: HTTP request
        tenant_id: Tenant ID
        saml_response: Base64-encoded SAML response
        relay_state: RelayState containing __test__:{idp_id}

    Returns:
        HTML response with test results
    """
    # Extract IdP ID from RelayState
    idp_id = relay_state.replace("__test__:", "")

    # Get stored test context
    expected_request_id = request.session.pop("saml_test_request_id", None)
    request.session.pop("saml_test_idp_id", None)  # Clear stored IdP ID

    # Build request data for python3-saml
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    request_data: dict[str, str | dict[str, str]] = {
        "https": "on" if forwarded_proto == "https" else "off",
        "http_host": request.headers.get("x-forwarded-host", request.url.netloc),
        "script_name": str(request.url.path),
        "get_data": {},
        "post_data": {},
    }

    # Process test response
    test_result = saml_service.process_saml_test_response(
        tenant_id=tenant_id,
        idp_id=idp_id,
        saml_response=saml_response,
        request_id=expected_request_id,
        request_data=request_data,
    )

    # Get IdP name for display
    try:
        idp = saml_service.get_idp_for_saml_login(tenant_id, idp_id)
        idp_name = idp.name
    except ServiceError:
        idp_name = "Unknown IdP"

    return templates.TemplateResponse(
        request,
        "saml_test_result.html",
        get_template_context(
            request,
            tenant_id,
            test_result=test_result,
            idp_id=idp_id,
            idp_name=idp_name,
        ),
    )


# ============================================================================
# Public SAML Endpoints
# ============================================================================


@router.get("/saml/metadata", response_class=Response)
def sp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """
    Return SP metadata XML for IdPs to consume.

    This is a public endpoint that IdPs use to configure SAML integration.
    """
    base_url = _get_base_url(request)

    try:
        xml = saml_service.get_tenant_sp_metadata_xml(tenant_id, base_url)
        return Response(content=xml, media_type="application/xml")
    except NotFoundError:
        # SP certificate not configured yet
        return Response(
            content="SP certificate not configured. Configure an IdP first.",
            status_code=404,
            media_type="text/plain",
        )


@router.get("/saml/login/{idp_id}")
def saml_login(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    idp_id: str,
):
    """
    Initiate SAML authentication flow.

    Redirects the user to the IdP's SSO URL with an AuthnRequest.
    """
    relay_state = request.query_params.get("relay_state", "/dashboard")

    try:
        redirect_url, request_id = saml_service.build_authn_request(tenant_id, idp_id, relay_state)

        # Store request_id in session for response validation
        request.session["saml_request_id"] = request_id
        request.session["saml_idp_id"] = idp_id

        return RedirectResponse(url=redirect_url, status_code=303)

    except NotFoundError as e:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {"error_type": "idp_not_found", "error_detail": str(e)},
        )
    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {"error_type": "configuration_error", "error_detail": str(e)},
        )


@router.post("/saml/acs")
def saml_acs(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    SAMLResponse: Annotated[str, Form()],  # noqa: N803 - SAML spec parameter name
    RelayState: Annotated[str, Form()] = "/dashboard",  # noqa: N803 - SAML spec parameter name
):
    """
    SAML Assertion Consumer Service (ACS).

    Receives and processes the SAML response from the IdP.
    Single endpoint for all IdPs - derives IdP from SAML response Issuer.
    Handles both real logins and connection testing (test mode via RelayState).
    """
    # Check if this is a test flow (RelayState starts with __test__:)
    if RelayState.startswith("__test__:"):
        return _handle_saml_test_response(request, tenant_id, SAMLResponse, RelayState)

    # Get stored request_id for validation
    expected_request_id = request.session.pop("saml_request_id", None)
    stored_idp_id = request.session.pop("saml_idp_id", None)

    # Prepare debug info (only used if IS_DEV is True)
    raw_saml_xml = _decode_saml_response_for_debug(SAMLResponse) if IS_DEV else None

    # Extract Issuer from SAML response to look up IdP
    issuer = extract_issuer_from_response(SAMLResponse)
    if not issuer:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": "invalid_response",
                "error_detail": "Could not extract Issuer from SAML response",
                "is_dev": IS_DEV,
                "raw_saml_xml": raw_saml_xml,
            },
        )

    # Look up IdP by issuer (entity_id)
    try:
        idp = saml_service.get_idp_by_issuer(tenant_id, issuer)
        idp_id = idp.id
    except NotFoundError:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": "idp_not_found",
                "error_detail": f"No IdP configured for issuer: {issuer}",
                "is_dev": IS_DEV,
                "raw_saml_xml": raw_saml_xml,
            },
        )
    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": "idp_disabled",
                "error_detail": str(e),
                "is_dev": IS_DEV,
                "raw_saml_xml": raw_saml_xml,
            },
        )

    # Verify IdP matches session (prevent response injection from different IdP)
    if stored_idp_id and stored_idp_id != idp_id:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": "invalid_response",
                "error_detail": "IdP mismatch - response from unexpected IdP",
                "is_dev": IS_DEV,
                "raw_saml_xml": raw_saml_xml,
            },
        )

    # Build request data for python3-saml
    # Check X-Forwarded-Proto header for reverse proxy, fall back to request scheme
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    request_data: dict[str, str | dict[str, str]] = {
        "https": "on" if forwarded_proto == "https" else "off",
        "http_host": request.headers.get("x-forwarded-host", request.url.netloc),
        "script_name": str(request.url.path),
        "get_data": {},
        "post_data": {},
    }

    try:
        # Process and validate SAML response
        saml_result = saml_service.process_saml_response(
            tenant_id=tenant_id,
            idp_id=idp_id,
            saml_response=SAMLResponse,
            request_id=expected_request_id,
            request_data=request_data,
        )

        # Complete authentication - lookup user
        user = saml_service.authenticate_via_saml(tenant_id, saml_result)

    except ValidationError as e:
        error_type = "signature_error" if "signature" in str(e).lower() else "invalid_response"
        if "expired" in str(e).lower():
            error_type = "expired"
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": error_type,
                "error_detail": str(e),
                "is_dev": IS_DEV,
                "raw_saml_xml": raw_saml_xml,
            },
        )
    except NotFoundError as e:
        if "user" in e.code.lower():
            email_detail = e.details.get("email") if e.details else None
            return templates.TemplateResponse(
                request,
                "saml_error.html",
                {
                    "error_type": "user_not_found",
                    "error_detail": email_detail,
                    "is_dev": IS_DEV,
                    "raw_saml_xml": raw_saml_xml,
                },
            )
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": "idp_not_found",
                "error_detail": str(e),
                "is_dev": IS_DEV,
                "raw_saml_xml": raw_saml_xml,
            },
        )
    except ServiceError as e:
        if "disabled" in str(e).lower():
            return templates.TemplateResponse(
                request,
                "saml_error.html",
                {
                    "error_type": "idp_disabled",
                    "error_detail": str(e),
                    "is_dev": IS_DEV,
                    "raw_saml_xml": raw_saml_xml,
                },
            )
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": "configuration_error",
                "error_detail": str(e),
                "is_dev": IS_DEV,
                "raw_saml_xml": raw_saml_xml,
            },
        )

    # Check if MFA is required
    if saml_result.requires_mfa and user.get("mfa_method"):
        # Store pending MFA info in session
        request.session["pending_mfa_user_id"] = str(user["id"])
        request.session["pending_mfa_method"] = user.get("mfa_method", "email")
        request.session["pending_saml_relay_state"] = RelayState

        return RedirectResponse(url="/mfa/verify", status_code=303)

    # Complete login - create session
    # Configure session persistence
    security_settings = settings_service.get_session_settings(tenant_id)
    if security_settings:
        persistent = security_settings.get("persistent_sessions", True)
        timeout = security_settings.get("session_timeout_seconds")
    else:
        persistent = True
        timeout = None

    if not persistent:
        max_age = None
    elif timeout:
        max_age = timeout
    else:
        max_age = 30 * 24 * 3600  # 30 days

    # CRITICAL: Regenerate session to prevent session fixation attacks
    # This clears all pre-auth data and creates a fresh authenticated session
    regenerate_session(request, str(user["id"]), max_age)

    # Update last login
    users_service.update_last_login(tenant_id, str(user["id"]))

    return RedirectResponse(url=RelayState, status_code=303)


@router.get("/saml/select")
def saml_select_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """
    Display IdP selection page when multiple IdPs are available.
    """
    # Get enabled IdPs
    idps = saml_service.get_enabled_idps_for_login(tenant_id)

    if not idps:
        return RedirectResponse(url="/login?error=no_sso", status_code=303)

    # If only one IdP, redirect directly
    if len(idps) == 1:
        relay_state = request.query_params.get("relay_state", "/dashboard")
        return RedirectResponse(
            url=f"/saml/login/{idps[0].id}?relay_state={relay_state}",
            status_code=303,
        )

    relay_state = request.query_params.get("relay_state", "")

    return templates.TemplateResponse(
        request,
        "saml_idp_select.html",
        {"idps": idps, "relay_state": relay_state},
    )


# ============================================================================
# Admin UI Endpoints (super_admin only)
# ============================================================================


@router.get(
    "/admin/identity-providers",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def list_idps(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List identity providers for admin management."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = _get_base_url(request)

    try:
        idp_list = saml_service.list_identity_providers(requesting_user)

        # Get SP metadata if certificate exists
        sp_metadata = None
        try:
            sp_metadata = saml_service.get_sp_metadata(requesting_user, base_url)
        except (NotFoundError, ServiceError):
            pass  # No SP cert yet

    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            get_template_context(
                request, tenant_id, error_type="configuration_error", error_detail=str(e)
            ),
        )

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "saml_idp_list.html",
        get_template_context(
            request,
            tenant_id,
            idps=idp_list.items,
            sp_metadata=sp_metadata,
            success=success,
            error=error,
        ),
    )


@router.get(
    "/admin/identity-providers/new",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def new_idp_form(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display form to create a new identity provider."""
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "saml_idp_form.html",
        get_template_context(request, tenant_id, idp=None, error=error),
    )


@router.post(
    "/admin/identity-providers/new",
    dependencies=[Depends(require_super_admin)],
)
def create_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: Annotated[str, Form()],
    provider_type: Annotated[str, Form()],
    entity_id: Annotated[str, Form()],
    sso_url: Annotated[str, Form()],
    certificate_pem: Annotated[str, Form()],
    slo_url: Annotated[str, Form()] = "",
    metadata_url: Annotated[str, Form()] = "",
    attr_email: Annotated[str, Form()] = "email",
    attr_first_name: Annotated[str, Form()] = "firstName",
    attr_last_name: Annotated[str, Form()] = "lastName",
    is_enabled: Annotated[bool, Form()] = False,
    is_default: Annotated[bool, Form()] = False,
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
):
    """Create a new identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = _get_base_url(request)

    data = IdPCreate(
        name=name,
        provider_type=provider_type,
        entity_id=entity_id,
        sso_url=sso_url,
        slo_url=slo_url or None,
        certificate_pem=certificate_pem,
        metadata_url=metadata_url or None,
        attribute_mapping={
            "email": attr_email,
            "first_name": attr_first_name,
            "last_name": attr_last_name,
        },
        is_enabled=is_enabled,
        is_default=is_default,
        require_platform_mfa=require_platform_mfa,
        jit_provisioning=jit_provisioning,
    )

    try:
        saml_service.create_identity_provider(requesting_user, data, base_url)
    except ValidationError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url="/admin/identity-providers?success=created", status_code=303)


@router.post(
    "/admin/identity-providers/import-metadata",
    dependencies=[Depends(require_super_admin)],
)
def import_from_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    metadata_url: Annotated[str, Form()],
    provider_type: Annotated[str, Form()],
    name: Annotated[str, Form()],
):
    """Import an IdP configuration from a metadata URL."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = _get_base_url(request)

    try:
        saml_service.import_idp_from_metadata_url(
            requesting_user, name, provider_type, metadata_url, base_url
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url="/admin/identity-providers?success=created", status_code=303)


@router.post(
    "/admin/identity-providers/import-metadata-xml",
    dependencies=[Depends(require_super_admin)],
)
def import_from_metadata_xml(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    metadata_xml: Annotated[str, Form()],
    provider_type: Annotated[str, Form()],
    name: Annotated[str, Form()],
):
    """Import an IdP configuration from raw metadata XML."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = _get_base_url(request)

    try:
        saml_service.import_idp_from_metadata_xml(
            requesting_user, name, provider_type, metadata_xml, base_url
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url="/admin/identity-providers?success=created", status_code=303)


@router.get(
    "/admin/identity-providers/{idp_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def edit_idp_form(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Display form to edit an identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = _get_base_url(request)

    try:
        idp = saml_service.get_identity_provider(requesting_user, idp_id)
        sp_metadata = saml_service.get_sp_metadata(requesting_user, base_url)

        # Get domain bindings for this IdP and unbound domains for binding
        domain_bindings = saml_service.list_domain_bindings(requesting_user, idp_id)
        unbound_domains = saml_service.get_unbound_domains(requesting_user)

    except NotFoundError:
        return RedirectResponse(url="/admin/identity-providers?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers?error={str(e)}",
            status_code=303,
        )

    error = request.query_params.get("error")
    success = request.query_params.get("success")

    return templates.TemplateResponse(
        request,
        "saml_idp_form.html",
        get_template_context(
            request,
            tenant_id,
            idp=idp,
            sp_metadata=sp_metadata,
            domain_bindings=domain_bindings.items,
            unbound_domains=unbound_domains,
            error=error,
            success=success,
        ),
    )


@router.get(
    "/admin/identity-providers/{idp_id}/test",
    dependencies=[Depends(require_super_admin)],
)
def test_idp_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """
    Initiate SAML test flow.

    Redirects to IdP with test=true in RelayState to distinguish from real logins.
    Opens in a new window (frontend handles this).
    """
    # Authorization handled by IsSuperAdmin dependency

    # Use special RelayState to indicate test mode
    relay_state = f"__test__:{idp_id}"

    try:
        redirect_url, request_id = saml_service.build_authn_request(tenant_id, idp_id, relay_state)

        # Store test context in session
        request.session["saml_test_request_id"] = request_id
        request.session["saml_test_idp_id"] = idp_id

        return RedirectResponse(url=redirect_url, status_code=303)

    except NotFoundError:
        return templates.TemplateResponse(
            request,
            "saml_test_result.html",
            get_template_context(
                request,
                tenant_id,
                test_result=SAMLTestResult(
                    success=False,
                    error_type="idp_not_found",
                    error_detail="Identity provider not found",
                ),
                idp_id=idp_id,
                idp_name="Unknown",
            ),
        )
    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "saml_test_result.html",
            get_template_context(
                request,
                tenant_id,
                test_result=SAMLTestResult(
                    success=False,
                    error_type="configuration_error",
                    error_detail=str(e),
                ),
                idp_id=idp_id,
                idp_name="Unknown",
            ),
        )


@router.post(
    "/admin/identity-providers/{idp_id}",
    dependencies=[Depends(require_super_admin)],
)
def update_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    name: Annotated[str, Form()],
    sso_url: Annotated[str, Form()],
    certificate_pem: Annotated[str, Form()],
    slo_url: Annotated[str, Form()] = "",
    metadata_url: Annotated[str, Form()] = "",
    attr_email: Annotated[str, Form()] = "email",
    attr_first_name: Annotated[str, Form()] = "firstName",
    attr_last_name: Annotated[str, Form()] = "lastName",
    is_enabled: Annotated[bool, Form()] = False,
    is_default: Annotated[bool, Form()] = False,
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
):
    """Update an identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    data = IdPUpdate(
        name=name,
        sso_url=sso_url,
        slo_url=slo_url or None,
        certificate_pem=certificate_pem,
        metadata_url=metadata_url or None,
        attribute_mapping={
            "email": attr_email,
            "first_name": attr_first_name,
            "last_name": attr_last_name,
        },
        require_platform_mfa=require_platform_mfa,
        jit_provisioning=jit_provisioning,
    )

    try:
        saml_service.update_identity_provider(requesting_user, idp_id, data)

        # Handle enable/disable and default separately
        idp = saml_service.get_identity_provider(requesting_user, idp_id)
        if idp.is_enabled != is_enabled:
            saml_service.set_idp_enabled(requesting_user, idp_id, is_enabled)
        if is_default and not idp.is_default:
            saml_service.set_idp_default(requesting_user, idp_id)

    except NotFoundError:
        return RedirectResponse(url="/admin/identity-providers?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/admin/identity-providers/{idp_id}?success=updated", status_code=303
    )


@router.post(
    "/admin/identity-providers/{idp_id}/toggle",
    dependencies=[Depends(require_super_admin)],
)
def toggle_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Toggle an IdP's enabled status."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        idp = saml_service.get_identity_provider(requesting_user, idp_id)
        saml_service.set_idp_enabled(requesting_user, idp_id, not idp.is_enabled)
    except NotFoundError:
        return RedirectResponse(url="/admin/identity-providers?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers?error={str(e)}",
            status_code=303,
        )

    success = "enabled" if not idp.is_enabled else "disabled"
    return RedirectResponse(url=f"/admin/identity-providers?success={success}", status_code=303)


@router.post(
    "/admin/identity-providers/{idp_id}/set-default",
    dependencies=[Depends(require_super_admin)],
)
def set_default_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Set an IdP as the default for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.set_idp_default(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url="/admin/identity-providers?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url="/admin/identity-providers?success=set_default", status_code=303)


@router.post(
    "/admin/identity-providers/{idp_id}/refresh-metadata",
    dependencies=[Depends(require_super_admin)],
)
def refresh_idp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Manually refresh an IdP's metadata from its URL."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.refresh_idp_from_metadata(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url="/admin/identity-providers?error=not_found", status_code=303)
    except ValidationError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/{idp_id}?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url="/admin/identity-providers?success=refreshed", status_code=303)


@router.post(
    "/admin/identity-providers/{idp_id}/delete",
    dependencies=[Depends(require_super_admin)],
)
def delete_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Delete an identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.delete_identity_provider(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url="/admin/identity-providers?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url="/admin/identity-providers?success=deleted", status_code=303)


# ============================================================================
# Domain Binding Web Routes (Phase 3)
# ============================================================================


@router.post(
    "/admin/identity-providers/{idp_id}/bind-domain",
    dependencies=[Depends(require_super_admin)],
)
def bind_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    domain_id: Annotated[str, Form()],
):
    """Bind a privileged domain to this IdP."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.bind_domain_to_idp(requesting_user, idp_id, domain_id)
    except NotFoundError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/admin/identity-providers/{idp_id}?success=domain_bound",
        status_code=303,
    )


@router.post(
    "/admin/identity-providers/{idp_id}/unbind-domain/{domain_id}",
    dependencies=[Depends(require_super_admin)],
)
def unbind_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    domain_id: str,
):
    """Unbind a domain from this IdP."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.unbind_domain_from_idp(requesting_user, domain_id)
    except NotFoundError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/admin/identity-providers/{idp_id}?success=domain_unbound",
        status_code=303,
    )
