"""Logout endpoint with SAML SLO support.

Architectural Note: This module contains direct log_event() calls for the user_signed_out
event. This is an accepted exception to the "event logging in services" pattern because
logout is fundamentally a session termination operation at the HTTP boundary, not a
business logic mutation.
"""

from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from services.event_log import log_event
from utils.request_metadata import extract_request_metadata

router = APIRouter()


@router.post("/logout")
def logout(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Handle logout with optional SAML SLO.

    If the user logged in via SAML and the IdP has SLO configured,
    initiates Single Logout by redirecting to the IdP. Otherwise,
    just clears the local session.

    SLO errors are logged but never block local logout.
    """
    from services import saml as saml_service

    # Get session data before clearing
    user_id = request.session.get("user_id")
    saml_idp_id = request.session.get("saml_idp_id")
    saml_name_id = request.session.get("saml_name_id")
    saml_name_id_format = request.session.get("saml_name_id_format")
    saml_session_index = request.session.get("saml_session_index")

    # Log the logout event before clearing session
    if user_id:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_signed_out",
            metadata={
                "saml_slo_attempted": saml_idp_id is not None and saml_name_id is not None,
            },
            request_metadata=extract_request_metadata(request),
        )

    # Clear local session first (critical - do this before SLO attempt)
    request.session.clear()

    # Attempt SLO if this was a SAML session
    if saml_idp_id and saml_name_id:
        try:
            # Get base URL for SLO callback
            host = request.headers.get("x-forwarded-host", request.url.netloc)
            base_url = f"https://{host}"

            slo_redirect = saml_service.initiate_sp_logout(
                tenant_id=tenant_id,
                saml_idp_id=saml_idp_id,
                name_id=saml_name_id,
                name_id_format=saml_name_id_format,
                session_index=saml_session_index,
                base_url=base_url,
            )
            if slo_redirect:
                return RedirectResponse(url=slo_redirect, status_code=303)
        except Exception:
            # SLO errors should NOT block logout - just log and continue
            import logging

            logging.getLogger(__name__).warning(
                f"SLO failed for user {user_id}, continuing with local logout"
            )

    return RedirectResponse(url="/login", status_code=303)
