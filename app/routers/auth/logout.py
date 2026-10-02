"""Logout endpoint, upstream logout hops, and the post-logout landing.

A WeftID sign-out continues at the upstream identity provider when the
session began there: SAML Single Logout (when the IdP has an SLO URL) or
OpenID Connect RP-Initiated Logout (when the connection has "sign out at the
provider" on). A logout an RP started through end_session keeps its return
address across that round trip in the (new, signed-out) session; the IdP
sends the browser back to ``/logout/complete`` (OIDC) or ``/saml/slo``
(SAML), which finish at it. The OIDC hop carries a ``state`` kept in the same
session; ``/logout/complete`` honours the stashed address only when the
provider echoes it back.

Architectural Note: This module contains direct log_event() calls for the user_signed_out
event. This is an accepted exception to the "event logging in services" pattern because
logout is fundamentally a session termination operation at the HTTP boundary, not a
business logic mutation.
"""

import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Annotated
from urllib.parse import urlsplit

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse, Response
from services import oidc as oidc_service
from services import oidc_upstream as oidc_upstream_service
from services.event_log import log_event
from services.oidc import OidcSessionEnd
from utils.csp_nonce import get_csp_nonce
from utils.redirects import safe_redirect
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

# Where the browser goes once an upstream logout round trip returns, when the
# logout was started by an RP through end_session (its verified
# post_logout_redirect_uri, or the signed-out page). Written into the
# signed-out session, so only this server can have put it there; short-lived
# and consumed on use.
PENDING_LOGOUT_RETURN_KEY = "pending_logout_return"
PENDING_LOGOUT_RETURN_MAX_AGE = 10 * 60

# The ``state`` sent with an upstream OIDC end_session request (RP-Initiated
# Logout 1.0, section 2), kept in the signed-out session. The provider echoes
# it to ``/logout/complete``; a missing or different value means the return
# is not the one this browser started, so the stashed address is dropped.
UPSTREAM_LOGOUT_STATE_KEY = "upstream_logout_state"


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
        upstream_oidc_logout_url: The upstream OIDC provider's end_session
            URL, when the session began at a connection with "sign out at the
            provider" on (read before the session's upstream link is removed).
        upstream_oidc_logout_state: The ``state`` that URL carries.
    """

    upstream: dict = field(default_factory=dict)
    frontchannel_logout_urls: list[str] = field(default_factory=list)
    backchannel_logout_count: int = 0
    upstream_oidc_logout_url: str | None = None
    upstream_oidc_logout_state: str | None = None


def _upstream_oidc_logout_url(request: Request, tenant_id: str, state: str) -> str | None:
    """The upstream OIDC end_session URL for the current session; never raises."""
    sid = request.session.get(SESSION_ID_KEY)
    if not isinstance(sid, str) or not sid:
        return None
    try:
        return oidc_upstream_service.build_upstream_logout_url(
            tenant_id=tenant_id,
            sid=sid,
            post_logout_redirect_uri=(
                f"{tenant_base_url(request)}{oidc_upstream_service.POST_LOGOUT_PATH}"
            ),
            state=state,
        )
    except Exception:
        logger.warning("Upstream OIDC logout URL could not be built", exc_info=True)
        return None


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
    ``backchannel_logout_count``, ``refresh_tokens_revoked`` and the
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

    # Before end_oidc_session forgets the session's upstream link.
    upstream_oidc_logout_state = secrets.token_urlsafe(24)
    upstream_oidc_logout_url = (
        _upstream_oidc_logout_url(request, tenant_id, upstream_oidc_logout_state)
        if user_id
        else None
    )

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
                "refresh_tokens_revoked": oidc_end.refresh_tokens_revoked,
                "upstream_oidc_logout": upstream_oidc_logout_url is not None,
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
        upstream_oidc_logout_url=upstream_oidc_logout_url,
        upstream_oidc_logout_state=upstream_oidc_logout_state if upstream_oidc_logout_url else None,
    )


def _upstream_saml_logout_url(
    request: Request, tenant_id: str, terminated: TerminatedSession
) -> str | None:
    """The signed SAML LogoutRequest URL at the upstream IdP; never raises."""
    from services import saml as saml_service

    upstream = terminated.upstream
    if not upstream.get("saml_idp_id") or not upstream.get("saml_name_id"):
        return None
    try:
        host = request.headers.get("x-forwarded-host", request.url.netloc)
        return saml_service.initiate_sp_logout(
            tenant_id=tenant_id,
            saml_idp_id=upstream["saml_idp_id"],
            name_id=upstream["saml_name_id"],
            name_id_format=upstream.get("saml_name_id_format"),
            session_index=upstream.get("saml_session_index"),
            base_url=f"https://{host}",
        )
    except Exception:
        logger.warning("SAML SLO could not be started, continuing with local logout")
        return None


def upstream_logout_response(
    request: Request,
    tenant_id: str,
    terminated: TerminatedSession,
    *,
    return_to: str | None = None,
) -> Response | None:
    """Continue a finished WeftID logout at the upstream identity provider.

    SAML Single Logout when the session came from a SAML IdP with an SLO URL,
    otherwise the upstream OIDC provider's end_session endpoint when the
    connection signs users out there. None when neither applies.

    ``return_to`` (a same-origin path, or an RP's verified
    post_logout_redirect_uri) is where the browser finishes once the IdP
    sends it back; it is stashed in the signed-out session. Without it the
    browser finishes on the login page.

    The OIDC hop always goes through a page (the front-channel page, which
    also loads RP logout iframes when there are any): a 303 off-origin after
    the logout form's POST is cut off by the form's CSP ``form-action`` in
    Chromium. The SAML hop's origin is allowed there already (the SLO URL is
    in the session), so it stays a redirect unless iframes must load first.
    """
    saml_url = _upstream_saml_logout_url(request, tenant_id, terminated)
    target = saml_url or terminated.upstream_oidc_logout_url
    if not target:
        return None
    if return_to:
        request.session[PENDING_LOGOUT_RETURN_KEY] = {"url": return_to, "at": int(time.time())}
    if saml_url is None and terminated.upstream_oidc_logout_state:
        request.session[UPSTREAM_LOGOUT_STATE_KEY] = terminated.upstream_oidc_logout_state
    if terminated.frontchannel_logout_urls or saml_url is None:
        return frontchannel_logout_response(request, terminated.frontchannel_logout_urls, target)
    # redirect-ok: external IdP SLO endpoint
    return RedirectResponse(url=target, status_code=303)


def pending_logout_return_response(request: Request) -> Response | None:
    """Finish an upstream logout round trip at the stashed destination.

    Pops the stash either way; None when there is none, or it is stale or
    malformed.
    """
    pending = request.session.pop(PENDING_LOGOUT_RETURN_KEY, None)
    if not isinstance(pending, dict):
        return None
    url = pending.get("url")
    at = pending.get("at")
    if (
        not isinstance(url, str)
        or not url
        or not isinstance(at, int)
        or time.time() - at > PENDING_LOGOUT_RETURN_MAX_AGE
    ):
        return None
    if url.startswith("/"):
        return safe_redirect(url)
    # Written by this server into the signed session after end_session matched
    # it exactly against the client's registered post_logout_redirect_uris.
    # redirect-ok: registered post_logout_redirect_uri, verified before stashing
    return RedirectResponse(url=url, status_code=303)


@router.post("/logout")
def logout(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """End the WeftID session, then the upstream IdP session when configured.

    SAML sessions continue to the IdP's Single Logout when it has an SLO URL;
    sessions from an upstream OIDC connection continue to its end_session
    endpoint when the connection signs users out there. Either way the local
    session is already gone; upstream errors never block the logout.
    """
    saml_idp_id = request.session.get("saml_idp_id")
    saml_name_id = request.session.get("saml_name_id")

    terminated = terminate_session(
        request,
        tenant_id,
        metadata={"saml_slo_attempted": saml_idp_id is not None and saml_name_id is not None},
    )

    upstream = upstream_logout_response(request, tenant_id, terminated)
    if upstream is not None:
        return upstream

    if terminated.frontchannel_logout_urls:
        return frontchannel_logout_response(request, terminated.frontchannel_logout_urls, "/login")
    return RedirectResponse(url="/login", status_code=303)


def _state_matches(expected: object, received: str | None) -> bool:
    if not isinstance(expected, str) or not expected or not received:
        return False
    return secrets.compare_digest(expected.encode(), received.encode())


@router.get(oidc_upstream_service.POST_LOGOUT_PATH)
def logout_complete(
    request: Request,
    state: Annotated[str | None, Query(max_length=2048)] = None,
):
    """Where an upstream OIDC provider returns the browser after logout.

    The post_logout_redirect_uri WeftID registers at upstream providers.
    Finishes at the destination an RP-started logout stashed when ``state``
    matches the one sent with the logout request, else the login page (a
    stash that came back without its state is dropped).

    Query parameters:
        state: The value WeftID sent with the end_session request, echoed by
            the provider.
    """
    expected = request.session.pop(UPSTREAM_LOGOUT_STATE_KEY, None)
    if _state_matches(expected, state):
        finish = pending_logout_return_response(request)
        if finish is not None:
            return finish
    elif request.session.pop(PENDING_LOGOUT_RETURN_KEY, None) is not None:
        logger.info("Upstream logout returned without the expected state; return dropped")
    return RedirectResponse(url="/login", status_code=303)
