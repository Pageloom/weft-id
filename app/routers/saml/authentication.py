"""SAML authentication endpoints: metadata, login initiation, and ACS."""

from typing import Annotated

import services.emails as emails_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse
from routers.saml._helpers import get_base_url, store_saml_debug_and_respond
from services import saml as saml_service
from services import settings as settings_service
from services import users as users_service
from services.branding import get_branding_for_template
from services.exceptions import NotFoundError, RateLimitError, ServiceError, ValidationError
from utils.csp_nonce import get_csp_nonce
from utils.email import send_mfa_code_email
from utils.mfa import create_email_otp
from utils.ratelimit import MINUTE, ratelimit
from utils.request_metadata import extract_remote_address
from utils.saml import extract_issuer_from_response
from utils.session import regenerate_session
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter()


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


@router.get("/saml/metadata/{idp_id}", response_class=Response)
def per_idp_sp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    idp_id: str,
):
    """
    Return per-IdP SP metadata XML.

    Each IdP gets its own EntityID, ACS URL, and signing certificate.
    This is the primary metadata endpoint for new IdPs.
    """
    import uuid as uuid_mod

    try:
        uuid_mod.UUID(idp_id)
    except ValueError:
        return Response(status_code=404, content="Not found", media_type="text/plain")

    base_url = get_base_url(request)

    try:
        xml = saml_service.get_idp_sp_metadata_xml(tenant_id, idp_id, base_url)
        return Response(content=xml, media_type="application/xml")
    except NotFoundError:
        return Response(
            content="Per-IdP SP certificate not configured.",
            status_code=404,
            media_type="text/plain",
        )


@router.get("/pub/idp/{idp_id}")
def public_trust_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    idp_id: str,
):
    """
    Public trust configuration page for external IdP administrators.

    Shows SP Entity ID, ACS URL, metadata URL, and expected attribute mappings
    so an external IdP admin can configure their side of the federation.
    """
    # Validate UUID format to avoid database errors
    import uuid as uuid_mod

    try:
        uuid_mod.UUID(idp_id)
    except ValueError:
        return Response(status_code=404, content="Not found", media_type="text/plain")

    base_url = get_base_url(request)

    try:
        trust_info = saml_service.get_public_trust_info(tenant_id, idp_id, base_url)
    except NotFoundError:
        return Response(status_code=404, content="Not found", media_type="text/plain")

    # Fetch per-IdP metadata XML for inline display
    metadata_xml = None
    try:
        metadata_xml = saml_service.get_idp_sp_metadata_xml(tenant_id, idp_id, base_url)
    except (NotFoundError, ServiceError):
        pass

    branding = get_branding_for_template(tenant_id)

    return templates.TemplateResponse(
        request,
        "saml_public_trust.html",
        {
            "request": request,
            "trust": trust_info,
            "metadata_xml": metadata_xml,
            "csp_nonce": get_csp_nonce(request),
            "branding": branding,
            "site_title": branding.get("site_title", "WeftID"),
        },
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
            {
                "error_type": "idp_not_found",
                "error_detail": str(e),
                "csp_nonce": get_csp_nonce(request),
            },
        )
    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {
                "error_type": "configuration_error",
                "error_detail": str(e),
                "csp_nonce": get_csp_nonce(request),
            },
        )


@router.post("/saml/acs/{idp_id}")
def saml_acs_per_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    idp_id: str,
    SAMLResponse: Annotated[str, Form()],  # noqa: N803 - SAML spec parameter name
    RelayState: Annotated[str, Form()] = "/dashboard",  # noqa: N803 - SAML spec parameter name
):
    """
    Per-IdP Assertion Consumer Service (ACS).

    Routes directly to the correct IdP without issuer extraction.
    Used by new IdPs with per-IdP EntityID format.
    """
    # Check if this is a test flow
    if RelayState.startswith("__test__:"):
        return _handle_saml_test_response(request, tenant_id, SAMLResponse, RelayState)

    # Rate limit ACS to prevent padding oracle queries
    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "saml_acs:tenant:{tenant_id}:ip:{ip}",
            limit=20,
            timespan=MINUTE * 5,
            tenant_id=tenant_id,
            ip=client_ip,
        )
    except RateLimitError:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {"error_type": "too_many_requests", "csp_nonce": get_csp_nonce(request)},
            status_code=429,
        )

    # Get stored request_id for validation
    expected_request_id = request.session.pop("saml_request_id", None)
    request.session.pop("saml_idp_id", None)

    # Check if verbose assertion logging is active for this IdP
    verbose_logging = saml_service.is_verbose_logging_active(tenant_id, idp_id)

    # Build request data for python3-saml
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    request_data: dict[str, str | dict[str, str]] = {
        "https": "on" if forwarded_proto == "https" else "off",
        "http_host": request.headers.get("x-forwarded-host", request.url.netloc),
        "script_name": str(request.url.path),
        "get_data": {},
        "post_data": {},
    }

    try:
        saml_result = saml_service.process_saml_response(
            tenant_id=tenant_id,
            idp_id=idp_id,
            saml_response=SAMLResponse,
            request_id=expected_request_id,
            request_data=request_data,
        )
        user = saml_service.authenticate_via_saml(tenant_id, saml_result)
    except ValidationError as e:
        if "expired" in str(e).lower():
            error_type = "expired"
        elif e.code == "saml_missing_email":
            error_type = "missing_attribute"
        else:
            error_type = "auth_failed"
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type=error_type,
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            verbose_event_logging=verbose_logging,
        )
    except NotFoundError as e:
        if "user" in e.code.lower():
            email_detail = e.details.get("email") if e.details else None
            return store_saml_debug_and_respond(
                request=request,
                tenant_id=tenant_id,
                error_type="user_not_found",
                error_detail=email_detail,
                saml_response_b64=SAMLResponse,
                idp_id=idp_id,
                verbose_event_logging=verbose_logging,
            )
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="idp_not_found",
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            verbose_event_logging=verbose_logging,
        )
    except ServiceError as e:
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="configuration_error",
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            verbose_event_logging=verbose_logging,
        )

    # Check if MFA is required
    if saml_result.requires_mfa and user.get("mfa_method"):
        request.session["pending_mfa_user_id"] = str(user["id"])
        request.session["pending_mfa_method"] = user.get("mfa_method", "email")
        request.session["pending_saml_relay_state"] = RelayState

        if user.get("mfa_method") == "email":
            code = create_email_otp(tenant_id, str(user["id"]))
            primary_email = emails_service.get_primary_email(tenant_id, str(user["id"]))
            if primary_email:
                send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

        return RedirectResponse(url="/mfa/verify", status_code=303)

    # Complete login
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
        max_age = 30 * 24 * 3600

    saml_session_data = {
        "saml_idp_id": saml_result.idp_id,
        "saml_name_id": saml_result.attributes.name_id,
        "saml_name_id_format": saml_result.name_id_format,
        "saml_session_index": saml_result.session_index,
        "saml_slo_url": saml_result.slo_url,
    }

    from routers.saml_idp._helpers import extract_pending_sso, get_post_auth_redirect

    pending_sso = extract_pending_sso(request.session)
    if pending_sso:
        saml_session_data.update(pending_sso)

    regenerate_session(request, str(user["id"]), max_age, additional_data=saml_session_data)
    users_service.update_last_login(tenant_id, str(user["id"]))

    redirect_url = get_post_auth_redirect(request.session, default=RelayState)
    return RedirectResponse(url=redirect_url, status_code=303)


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

    # Rate limit ACS to prevent padding oracle queries
    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "saml_acs:tenant:{tenant_id}:ip:{ip}",
            limit=20,
            timespan=MINUTE * 5,
            tenant_id=tenant_id,
            ip=client_ip,
        )
    except RateLimitError:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            {"error_type": "too_many_requests", "csp_nonce": get_csp_nonce(request)},
            status_code=429,
        )

    # Get stored request_id for validation
    expected_request_id = request.session.pop("saml_request_id", None)
    stored_idp_id = request.session.pop("saml_idp_id", None)

    # Extract Issuer from SAML response to look up IdP
    issuer = extract_issuer_from_response(SAMLResponse)
    if not issuer:
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="invalid_response",
            error_detail="Could not extract Issuer from SAML response",
            saml_response_b64=SAMLResponse,
        )

    # Look up IdP by issuer (entity_id)
    try:
        idp = saml_service.get_idp_by_issuer(tenant_id, issuer)
        idp_id = idp.id
        idp_name = idp.name
    except NotFoundError:
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="idp_not_found",
            error_detail=f"No IdP configured for issuer: {issuer}",
            saml_response_b64=SAMLResponse,
        )
    except ServiceError as e:
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="idp_disabled",
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
        )

    # Check if verbose assertion logging is active for this IdP
    verbose_logging = saml_service.is_verbose_logging_active(tenant_id, idp_id)

    # Verify IdP matches session (prevent response injection from different IdP)
    if stored_idp_id and stored_idp_id != idp_id:
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="invalid_response",
            error_detail="IdP mismatch - response from unexpected IdP",
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            idp_name=idp_name,
            verbose_event_logging=verbose_logging,
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
        if "expired" in str(e).lower():
            error_type = "expired"
        elif e.code == "saml_missing_email":
            error_type = "missing_attribute"
        else:
            error_type = "auth_failed"
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type=error_type,
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            idp_name=idp_name,
            verbose_event_logging=verbose_logging,
        )
    except NotFoundError as e:
        if "user" in e.code.lower():
            email_detail = e.details.get("email") if e.details else None
            return store_saml_debug_and_respond(
                request=request,
                tenant_id=tenant_id,
                error_type="user_not_found",
                error_detail=email_detail,
                saml_response_b64=SAMLResponse,
                idp_id=idp_id,
                idp_name=idp_name,
                verbose_event_logging=verbose_logging,
            )
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="idp_not_found",
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            idp_name=idp_name,
            verbose_event_logging=verbose_logging,
        )
    except ServiceError as e:
        if "disabled" in str(e).lower():
            return store_saml_debug_and_respond(
                request=request,
                tenant_id=tenant_id,
                error_type="idp_disabled",
                error_detail=str(e),
                saml_response_b64=SAMLResponse,
                idp_id=idp_id,
                idp_name=idp_name,
                verbose_event_logging=verbose_logging,
            )
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="configuration_error",
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            idp_name=idp_name,
            verbose_event_logging=verbose_logging,
        )

    # Check if MFA is required
    if saml_result.requires_mfa and user.get("mfa_method"):
        # Store pending MFA info in session
        request.session["pending_mfa_user_id"] = str(user["id"])
        request.session["pending_mfa_method"] = user.get("mfa_method", "email")
        request.session["pending_saml_relay_state"] = RelayState

        # If email MFA, send code immediately
        if user.get("mfa_method") == "email":
            code = create_email_otp(tenant_id, str(user["id"]))
            primary_email = emails_service.get_primary_email(tenant_id, str(user["id"]))
            if primary_email:
                send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

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
    # Include SAML session data for SLO support (Phase 4)
    saml_session_data = {
        "saml_idp_id": saml_result.idp_id,
        "saml_name_id": saml_result.attributes.name_id,
        "saml_name_id_format": saml_result.name_id_format,
        "saml_session_index": saml_result.session_index,
        "saml_slo_url": saml_result.slo_url,
    }

    # Preserve pending SSO context through session regeneration
    from routers.saml_idp._helpers import extract_pending_sso, get_post_auth_redirect

    pending_sso = extract_pending_sso(request.session)
    if pending_sso:
        saml_session_data.update(pending_sso)

    regenerate_session(request, str(user["id"]), max_age, additional_data=saml_session_data)

    # Update last login
    users_service.update_last_login(tenant_id, str(user["id"]))

    # Redirect to consent page if pending SSO, otherwise use RelayState
    redirect_url = get_post_auth_redirect(request.session, default=RelayState)
    return RedirectResponse(url=redirect_url, status_code=303)
