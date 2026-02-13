"""Logout endpoint with SAML SLO support.

Architectural Note: This module contains direct log_event() calls for the user_signed_out
event. This is an accepted exception to the "event logging in services" pattern because
logout is fundamentally a session termination operation at the HTTP boundary, not a
business logic mutation.
"""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from services.event_log import log_event
from utils.request_metadata import extract_request_metadata

logger = logging.getLogger(__name__)

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
    from services.service_providers.slo import propagate_logout_to_sps

    # Get session data before clearing
    user_id = request.session.get("user_id")
    saml_idp_id = request.session.get("saml_idp_id")
    saml_name_id = request.session.get("saml_name_id")
    saml_name_id_format = request.session.get("saml_name_id_format")
    saml_session_index = request.session.get("saml_session_index")

    # Get active downstream SP sessions before clearing
    active_sps = request.session.get("sso_active_sps", [])

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
                "downstream_sp_count": len(active_sps),
            },
            request_metadata=extract_request_metadata(request),
        )

    # Clear local session first (critical - do this before SLO attempt)
    request.session.clear()

    # Propagate logout to downstream SPs (best-effort, non-blocking)
    if active_sps and user_id:
        try:
            host = request.headers.get("x-forwarded-host", request.url.netloc)
            base_url = f"https://{host}"
            propagate_logout_to_sps(
                tenant_id=tenant_id,
                user_id=user_id,
                active_sps=active_sps,
                base_url=base_url,
            )
        except Exception:
            logger.warning("IdP SLO propagation failed for user %s", user_id, exc_info=True)

    # Attempt upstream SLO if this was a SAML session
    if saml_idp_id and saml_name_id:
        try:
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
            logger.warning("SLO failed for user %s, continuing with local logout", user_id)

    return RedirectResponse(url="/login", status_code=303)
