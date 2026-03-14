"""SAML IdP SSO endpoint and consent flow.

Handles SP-Initiated SSO:
1. SP sends AuthnRequest to /saml/idp/sso (GET or POST)
2. If user is not authenticated, redirect to /login (SSO context stored in session)
3. If authenticated, redirect to /saml/idp/consent
4. Consent form submits to /saml/idp/consent (POST)
5. On "continue": build signed SAML Response, render auto-submit form to SP's ACS URL
6. On "cancel": clear SSO context, redirect to /dashboard
"""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from services import branding as branding_service
from services import service_providers as sp_service
from services.event_log import log_event
from utils.csp_nonce import get_csp_nonce
from utils.saml_authn_request import parse_authn_request, validate_authn_request
from utils.template_context import get_template_context
from utils.templates import templates

from ._helpers import PENDING_SSO_KEYS, get_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/saml/idp",
    tags=["saml-idp-sso"],
    include_in_schema=False,
)


# ============================================================================
# SSO Endpoint (receives AuthnRequest from SPs)
# ============================================================================


@router.get("/sso")
def sso_redirect(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    SAMLRequest: str = Query(default=None),  # noqa: N803 - SAML spec parameter name
    RelayState: str = Query(default=None),  # noqa: N803 - SAML spec parameter name
):
    """HTTP-Redirect binding: SP sends AuthnRequest via query params."""
    if not SAMLRequest:
        return _render_sso_error(
            request, tenant_id, "invalid_request", "Missing SAMLRequest parameter"
        )

    return _handle_sso_request(request, tenant_id, SAMLRequest, RelayState, binding="redirect")


@router.post("/sso")
async def sso_post(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """HTTP-POST binding: SP sends AuthnRequest via form POST."""
    form = await request.form()
    saml_request = form.get("SAMLRequest")
    relay_state = form.get("RelayState")

    if not saml_request:
        return _render_sso_error(
            request, tenant_id, "invalid_request", "Missing SAMLRequest parameter"
        )

    return _handle_sso_request(
        request,
        tenant_id,
        str(saml_request),
        str(relay_state) if relay_state else None,
        binding="post",
    )


def _handle_sso_request(
    request: Request,
    tenant_id: str,
    saml_request: str,
    relay_state: str | None,
    binding: str,
) -> RedirectResponse | HTMLResponse:
    """Common handler for both GET and POST SSO bindings."""
    # 1. Parse AuthnRequest
    try:
        parsed = parse_authn_request(saml_request, binding)
    except ValueError as e:
        logger.warning("Invalid AuthnRequest: %s", e)
        return _render_sso_error(request, tenant_id, "invalid_request", str(e))

    # 2. Look up SP by issuer
    issuer = parsed["issuer"]
    if not issuer:
        return _render_sso_error(request, tenant_id, "invalid_request", "Missing issuer")
    sp = sp_service.get_sp_by_entity_id(tenant_id, issuer)
    if sp is None:
        logger.warning("Unknown SP entity_id: %s", issuer)
        return _render_sso_error(request, tenant_id, "unknown_sp")

    # 2b. Reject SPs where trust has not been established
    if not sp.trust_established:
        logger.warning("SSO request for pending SP (trust not established): %s", issuer)
        return _render_sso_error(request, tenant_id, "sp_pending_trust")

    # 2c. Reject disabled SPs
    if not sp.enabled:
        logger.warning("SSO request for disabled SP: %s", issuer)
        return _render_sso_error(request, tenant_id, "sp_disabled")

    # 3. Validate request against registered SP (ACS URL match etc.)
    sp_dict = {"entity_id": sp.entity_id, "acs_url": sp.acs_url}
    try:
        validate_authn_request(parsed, sp_dict)
    except ValueError as e:
        logger.warning("AuthnRequest validation failed: %s", e)
        return _render_sso_error(request, tenant_id, "invalid_request", str(e))

    # 4. Store SSO context in session
    request.session["pending_sso_sp_id"] = sp.id
    request.session["pending_sso_sp_entity_id"] = sp.entity_id
    request.session["pending_sso_authn_request_id"] = parsed["id"]
    request.session["pending_sso_relay_state"] = relay_state or ""
    request.session["pending_sso_sp_name"] = sp.name

    # 5. Check if user is already authenticated
    user_id = request.session.get("user_id")
    if user_id:
        # Bind SSO context to this user so no other user can complete it
        request.session["pending_sso_user_id"] = user_id
        # User is authenticated, go straight to consent
        return RedirectResponse(url="/saml/idp/consent", status_code=303)
    else:
        # User needs to log in first; pending_sso_user_id will be stamped
        # after successful authentication in the MFA verification handler
        return RedirectResponse(url="/login", status_code=303)


# ============================================================================
# Consent Screen
# ============================================================================


@router.get("/consent")
def consent_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Render consent screen showing what attributes will be shared."""
    # Require authenticated session
    user_id = request.session.get("user_id")
    if not user_id:
        return _render_sso_error(request, tenant_id, "no_session")

    # Require pending SSO context
    sp_entity_id = request.session.get("pending_sso_sp_entity_id")
    if not sp_entity_id:
        return _render_sso_error(request, tenant_id, "no_pending_sso")

    # Verify SSO context is bound to this user
    bound_user_id = request.session.get("pending_sso_user_id")
    if bound_user_id and bound_user_id != user_id:
        logger.warning(
            "SSO context bound to user %s but current user is %s", bound_user_id, user_id
        )
        return _render_sso_error(request, tenant_id, "no_pending_sso")

    sp_id = request.session.get("pending_sso_sp_id", "")
    sp_name = request.session.get("pending_sso_sp_name", "Unknown Application")

    # Check group-based access
    if sp_id and not sp_service.check_user_sp_access(tenant_id, user_id, sp_id):
        return _render_sso_error(request, tenant_id, "unauthorized_user")

    # Get user info for the consent screen
    user_info = sp_service.get_user_consent_info(tenant_id, user_id)
    if not user_info:
        return _render_sso_error(request, tenant_id, "no_session")

    # Get SP logo info for the consent screen
    sp_has_logo = False
    sp_logo_updated_at = None
    if sp_id:
        logo_data = branding_service.get_sp_logo_for_serving(tenant_id, sp_id)
        if logo_data:
            sp_has_logo = True
            sp_logo_updated_at = int(logo_data["updated_at"].timestamp())

    context = get_template_context(
        request,
        tenant_id,
        sp_id=sp_id,
        sp_name=sp_name,
        sp_has_logo=sp_has_logo,
        sp_logo_updated_at=sp_logo_updated_at,
        user_email=user_info["email"],
        user_first_name=user_info["first_name"],
        user_last_name=user_info["last_name"],
    )

    return templates.TemplateResponse(request, "saml_idp_sso_consent.html", context)


@router.post("/consent/switch-account")
def consent_switch_account(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Clear auth session but preserve SSO context, then redirect to login."""
    # Save pending SSO context (excludes pending_sso_user_id so it gets
    # re-bound to whichever user authenticates next)
    saved = {
        k: request.session.get(k) for k in PENDING_SSO_KEYS if request.session.get(k) is not None
    }

    # Log the sign-out event before clearing
    user_id = request.session.get("user_id")
    if user_id:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_signed_out",
            metadata={"reason": "sso_switch_account"},
        )

    # Clear entire session (removes auth state)
    request.session.clear()

    # Restore SSO context so login redirects back to consent
    for k, v in saved.items():
        request.session[k] = v

    return RedirectResponse(url="/login", status_code=303)


@router.post("/consent")
def consent_respond(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    action: str = Form(...),
):
    """Process consent form submission."""
    # Require authenticated session
    user_id = request.session.get("user_id")
    if not user_id:
        return _render_sso_error(request, tenant_id, "no_session")

    # Require pending SSO context
    sp_entity_id = request.session.get("pending_sso_sp_entity_id")
    if not sp_entity_id:
        return _render_sso_error(request, tenant_id, "no_pending_sso")

    # Verify SSO context is bound to this user
    bound_user_id = request.session.get("pending_sso_user_id")
    if bound_user_id and bound_user_id != user_id:
        logger.warning(
            "SSO context bound to user %s but current user is %s", bound_user_id, user_id
        )
        return _render_sso_error(request, tenant_id, "no_pending_sso")

    sp_id = request.session.get("pending_sso_sp_id", "")
    authn_request_id = request.session.get("pending_sso_authn_request_id")
    relay_state = request.session.get("pending_sso_relay_state", "")
    sp_name = request.session.get("pending_sso_sp_name", "")

    # Clear pending SSO context from session regardless of action
    for key in (*PENDING_SSO_KEYS, "pending_sso_user_id"):
        request.session.pop(key, None)

    if action == "cancel":
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="service_provider",
            artifact_id=sp_id,
            event_type="sso_consent_denied",
            metadata={
                "sp_entity_id": sp_entity_id,
                "sp_name": sp_name,
            },
        )
        return RedirectResponse(url="/dashboard", status_code=303)

    # action == "continue": build SAML Response
    base_url = get_base_url(request)

    try:
        saml_response_b64, acs_url, session_index = sp_service.build_sso_response(
            tenant_id=tenant_id,
            user_id=user_id,
            sp_entity_id=sp_entity_id,
            authn_request_id=authn_request_id,
            base_url=base_url,
        )
    except Exception as e:
        logger.error("Failed to build SSO response: %s", e)
        return _render_sso_error(request, tenant_id, "no_certificate", str(e))

    # Track active SP session for SLO propagation
    active_sps = request.session.get("sso_active_sps", [])
    active_sps.append(
        {
            "sp_id": sp_id,
            "sp_entity_id": sp_entity_id,
            "name_id": user_id,
            "session_index": session_index,
        }
    )
    request.session["sso_active_sps"] = active_sps

    # Render auto-submit form to POST assertion to SP's ACS URL
    csp_nonce = get_csp_nonce(request)
    # Allow form submission to the SP's ACS URL in CSP
    request.state.csp_form_action_url = acs_url
    return templates.TemplateResponse(
        request,
        "saml_idp_sso_post.html",
        {
            "acs_url": acs_url,
            "saml_response": saml_response_b64,
            "relay_state": relay_state if relay_state else None,
            "csp_nonce": csp_nonce,
        },
    )


# ============================================================================
# IdP-Initiated SSO (launch from dashboard)
# ============================================================================


@router.get("/launch/{sp_id}")
def idp_initiated_launch(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    sp_id: str,
):
    """Launch IdP-initiated SSO for a service provider.

    User clicks an app tile on the dashboard. We look up the SP, check access
    via group assignments, store SSO context in session, and redirect to consent.
    """
    # Require authenticated session
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)

    # Look up SP by ID
    sp_row = sp_service.get_service_provider_by_id(tenant_id, sp_id)
    if sp_row is None:
        return _render_sso_error(request, tenant_id, "unknown_sp")

    # Reject SPs where trust has not been established
    if not sp_row.get("trust_established", False):
        return _render_sso_error(request, tenant_id, "sp_pending_trust")

    # Reject disabled SPs
    if not sp_row.get("enabled", True):
        return _render_sso_error(request, tenant_id, "sp_disabled")

    # Check group-based access
    if not sp_service.check_user_sp_access(tenant_id, user_id, sp_id):
        return _render_sso_error(request, tenant_id, "unauthorized_user")

    # Store SSO context in session (authn_request_id=None for IdP-initiated)
    request.session["pending_sso_sp_id"] = sp_id
    request.session["pending_sso_sp_entity_id"] = sp_row["entity_id"]
    request.session["pending_sso_authn_request_id"] = None
    request.session["pending_sso_relay_state"] = ""
    request.session["pending_sso_sp_name"] = sp_row["name"]
    request.session["pending_sso_user_id"] = user_id

    # Redirect to consent page (reuses existing consent flow)
    return RedirectResponse(url="/saml/idp/consent", status_code=303)


# ============================================================================
# Error Rendering
# ============================================================================


def _render_sso_error(
    request: Request,
    tenant_id: str,
    error_type: str,
    error_detail: str | None = None,
) -> HTMLResponse:
    """Render the SSO error page."""
    context = get_template_context(
        request,
        tenant_id,
        error_type=error_type,
        error_detail=error_detail,
    )
    return templates.TemplateResponse(
        request,
        "saml_idp_sso_error.html",
        context,
        status_code=400,
    )
