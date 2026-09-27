"""Logout endpoint with SAML SLO support.

Architectural Note: This module contains direct log_event() calls for the user_signed_out
event. This is an accepted exception to the "event logging in services" pattern because
logout is fundamentally a session termination operation at the HTTP boundary, not a
business logic mutation.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Annotated
from urllib.parse import urlsplit

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response
from services import oidc as oidc_service
from services.event_log import log_event
from services.oidc import OidcSessionEnd
from utils.csp_nonce import get_csp_nonce
from utils.request_metadata import extract_request_metadata
from utils.session import SESSION_ID_KEY
from utils.templates import templates
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter()

# What may appear in a CSP frame-src source built from a registered URI. The
# URIs are validated at registration; this keeps a header value from ever
# carrying anything but a plain origin.
_CSP_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?$")


@dataclass(frozen=True)
class TerminatedSession:
    """What a caller needs after ``terminate_session`` cleared the session.

    Attributes:
        upstream: The upstream SAML session context read before clearing
            (``saml_idp_id``, ``saml_name_id``, ``saml_name_id_format``,
            ``saml_session_index``; values may be None), for a caller that
            continues with upstream Single Logout.
        frontchannel_logout_urls: OIDC front-channel logout URLs of the
            relying parties that received ID tokens in the session. The
            caller renders them with ``frontchannel_logout_response``.
        backchannel_logout_count: OIDC back-channel logout deliveries queued
            for the worker.
    """

    upstream: dict = field(default_factory=dict)
    frontchannel_logout_urls: list[str] = field(default_factory=list)
    backchannel_logout_count: int = 0


def end_oidc_session_quietly(
    request: Request,
    tenant_id: str,
    *,
    exclude_client_uuid: str | None = None,
) -> OidcSessionEnd:
    """Notify the current session's OIDC relying parties; never raises.

    Returns the front-channel logout URLs to load and the number of
    back-channel deliveries queued. A failure is logged and notifies nobody:
    logout must not fail because relying-party bookkeeping could not be read.
    """
    sid = request.session.get(SESSION_ID_KEY)
    if not isinstance(sid, str) or not sid:
        return OidcSessionEnd()
    try:
        return oidc_service.end_oidc_session(
            tenant_id=tenant_id,
            issuer=tenant_base_url(request),
            sid=sid,
            exclude_client_uuid=exclude_client_uuid,
        )
    except Exception:
        logger.warning("OIDC logout fan-out failed", exc_info=True)
        return OidcSessionEnd()


def frontchannel_logout_response(
    request: Request, frontchannel_logout_urls: list[str], continue_url: str
) -> Response:
    """Render the page that loads the RPs' logout iframes, then moves on.

    The page continues to ``continue_url`` once every iframe has loaded (a
    declarative refresh), after five seconds at most (script), or when the
    user clicks Continue. ``continue_url`` must already be trusted: a
    same-origin path or a verified registered URI. The CSP ``frame-src`` is
    widened to the RP origins, and the page is never cached.
    """
    origins: list[str] = []
    for url in frontchannel_logout_urls:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if _CSP_ORIGIN.match(origin) and origin not in origins:
            origins.append(origin)
    request.state.csp_frame_src_origins = origins
    response = templates.TemplateResponse(
        request,
        "oauth2_logout_frontchannel.html",
        {
            "frontchannel_logout_urls": frontchannel_logout_urls,
            "continue_url": continue_url,
            "nav": {},
            "csp_nonce": get_csp_nonce(request),
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def terminate_session(
    request: Request,
    tenant_id: str,
    *,
    metadata: dict | None = None,
) -> TerminatedSession:
    """End the WeftID session: audit, clear, and notify relying parties.

    Shared by the local logout button and the OIDC end_session endpoint so
    both terminate a session the same way. When a user was signed in, reads
    the OIDC clients to notify (front-channel URLs; back-channel deliveries
    are queued), logs ``user_signed_out``
    (with ``downstream_sp_count``, ``frontchannel_logout_count``,
    ``backchannel_logout_count`` and the
    caller's ``metadata``), clears the session before anything else can fail,
    then propagates the logout to downstream SAML SPs (best-effort, never
    blocks).

    Returns:
        The upstream SAML context and the front-channel logout URLs.
    """
    from services.service_providers.slo import propagate_logout_to_sps

    # Get session data before clearing
    user_id = request.session.get("user_id")
    upstream = {
        key: request.session.get(key)
        for key in ("saml_idp_id", "saml_name_id", "saml_name_id_format", "saml_session_index")
    }

    # Get active downstream SP sessions before clearing
    active_sps = request.session.get("sso_active_sps", [])

    oidc_end = end_oidc_session_quietly(request, tenant_id) if user_id else OidcSessionEnd()

    # Log the logout event before clearing session
    if user_id:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_signed_out",
            metadata={
                "downstream_sp_count": len(active_sps),
                "frontchannel_logout_count": len(oidc_end.frontchannel_logout_urls),
                "backchannel_logout_count": oidc_end.backchannel_logout_count,
                **(metadata or {}),
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

    return TerminatedSession(
        upstream=upstream,
        frontchannel_logout_urls=oidc_end.frontchannel_logout_urls,
        backchannel_logout_count=oidc_end.backchannel_logout_count,
    )


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

    user_id = request.session.get("user_id")
    saml_idp_id = request.session.get("saml_idp_id")
    saml_name_id = request.session.get("saml_name_id")

    terminated = terminate_session(
        request,
        tenant_id,
        metadata={"saml_slo_attempted": saml_idp_id is not None and saml_name_id is not None},
    )
    upstream = terminated.upstream

    # Attempt upstream SLO if this was a SAML session
    if saml_idp_id and saml_name_id:
        try:
            host = request.headers.get("x-forwarded-host", request.url.netloc)
            base_url = f"https://{host}"

            slo_redirect = saml_service.initiate_sp_logout(
                tenant_id=tenant_id,
                saml_idp_id=saml_idp_id,
                name_id=saml_name_id,
                name_id_format=upstream["saml_name_id_format"],
                session_index=upstream["saml_session_index"],
                base_url=base_url,
            )
            if slo_redirect:
                if terminated.frontchannel_logout_urls:
                    return frontchannel_logout_response(
                        request, terminated.frontchannel_logout_urls, slo_redirect
                    )
                # redirect-ok: external IdP SLO endpoint
                return RedirectResponse(url=slo_redirect, status_code=303)
        except Exception:
            logger.warning("SLO failed for user %s, continuing with local logout", user_id)

    if terminated.frontchannel_logout_urls:
        return frontchannel_logout_response(request, terminated.frontchannel_logout_urls, "/login")
    return RedirectResponse(url="/login", status_code=303)
