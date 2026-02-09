"""SAML authentication endpoints: metadata, login initiation, and ACS."""

from typing import Annotated

import services.emails as emails_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from routers.saml._helpers import get_base_url, store_saml_debug_and_respond
from services import saml as saml_service
from services import settings as settings_service
from services import users as users_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.csp_nonce import get_csp_nonce
from utils.email import send_mfa_code_email
from utils.mfa import create_email_otp
from utils.saml import extract_issuer_from_response
from utils.session import regenerate_session
from utils.template_context import get_template_context

router = APIRouter()
templates = Jinja2Templates(directory="templates")


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


@router.get("/saml/metadata", response_class=Response)
def sp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """
    Return SP metadata XML for IdPs to consume.

    This is a public endpoint that IdPs use to configure SAML integration.
    """
    base_url = get_base_url(request)

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
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type=error_type,
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            idp_name=idp_name,
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
            )
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="idp_not_found",
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            idp_name=idp_name,
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
            )
        return store_saml_debug_and_respond(
            request=request,
            tenant_id=tenant_id,
            error_type="configuration_error",
            error_detail=str(e),
            saml_response_b64=SAMLResponse,
            idp_id=idp_id,
            idp_name=idp_name,
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
                send_mfa_code_email(primary_email, code)

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
    }
    regenerate_session(request, str(user["id"]), max_age, additional_data=saml_session_data)

    # Update last login
    users_service.update_last_login(tenant_id, str(user["id"]))

    return RedirectResponse(url=RelayState, status_code=303)
