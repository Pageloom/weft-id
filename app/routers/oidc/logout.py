"""OIDC end_session endpoint (OpenID Connect RP-Initiated Logout 1.0).

A relying party sends the browser here to end the user's WeftID session:

* With a verified ``id_token_hint`` for the signed-in user (or when nobody
  is signed in), the session ends at once. The browser then goes to the
  ``post_logout_redirect_uri`` (with ``state``) when the RP registered it,
  otherwise to the signed-out page.
* Anything else (no hint, a hint that fails verification or names another
  user, an unregistered or unverifiable ``post_logout_redirect_uri``) shows a
  confirmation page. Confirming ends the session and lands on the signed-out
  page; WeftID never redirects to an RP it could not verify.

Pages are server-rendered and work without JavaScript. Ending a session goes
through ``routers.auth.logout.terminate_session``, the same path as the
logout button (audit event, downstream SAML SP propagation). When relying
parties registered front-channel logout, an intermediate page loads their
iframes before the browser continues to its destination (OpenID Connect
Front-Channel Logout 1.0). When the session began at an upstream IdP that
WeftID signs users out of (SAML Single Logout, or an upstream OIDC connection
with "sign out at the provider" on), the browser goes there first; the
destination is stashed in the signed-out session and reached when the IdP
sends the browser back (``routers.auth.logout.upstream_logout_response``).
"""

import logging
from typing import Annotated
from urllib.parse import urlencode

from dependencies import get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from middleware.csrf import make_csrf_token_func
from routers.auth.logout import (
    frontchannel_logout_response,
    terminate_session,
    upstream_logout_response,
)
from services import oidc as oidc_service
from services.oidc.logout import EndSessionRequest
from utils.csp_nonce import get_csp_nonce
from utils.templates import templates
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["oidc"], include_in_schema=False)

# Path of the page shown after a session ends without an RP redirect. The
# redirects below spell it out as a literal (the redirect-validation compliance
# check accepts only literal same-origin targets).
SIGNED_OUT_PATH = "/oauth2/logout/done"


@router.get("/oauth2/logout", response_class=HTMLResponse)
def end_session(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict | None, Depends(get_current_user)],
    id_token_hint: Annotated[str | None, Query(max_length=8192)] = None,
    client_id: Annotated[str | None, Query(max_length=255)] = None,
    post_logout_redirect_uri: Annotated[str | None, Query(max_length=2048)] = None,
    state: Annotated[str | None, Query(max_length=2048)] = None,
    logout_hint: Annotated[str | None, Query(max_length=320)] = None,
    ui_locales: Annotated[str | None, Query(max_length=255)] = None,
):
    """
    OIDC end_session endpoint (GET).

    Query Parameters (OpenID Connect RP-Initiated Logout 1.0, section 2):
        id_token_hint: A WeftID-issued ID token for this client (expiry not
            enforced). RECOMMENDED; required for any redirect back to the RP.
        client_id: The RP's client_id. Must match the hint's audience when
            both are sent.
        post_logout_redirect_uri: Where to send the browser afterwards. Exact
            match against the client's registered post-logout redirect URIs,
            honoured only with a verified id_token_hint.
        state: Opaque value echoed to the post_logout_redirect_uri.
        logout_hint, ui_locales: Accepted and ignored.
    """
    return _handle_end_session(
        request, tenant_id, user, id_token_hint, client_id, post_logout_redirect_uri, state
    )


@router.post("/oauth2/logout", response_class=HTMLResponse)
def end_session_post(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict | None, Depends(get_current_user)],
    id_token_hint: Annotated[str | None, Form(max_length=8192)] = None,
    client_id: Annotated[str | None, Form(max_length=255)] = None,
    post_logout_redirect_uri: Annotated[str | None, Form(max_length=2048)] = None,
    state: Annotated[str | None, Form(max_length=2048)] = None,
    logout_hint: Annotated[str | None, Form(max_length=320)] = None,
    ui_locales: Annotated[str | None, Form(max_length=255)] = None,
):
    """
    OIDC end_session endpoint (POST).

    Accepts the same parameters as the GET form as form-encoded body fields
    (the spec requires both methods) and behaves identically. Exempt from
    CSRF validation because the request comes from the relying party; it can
    only end the session without asking when it carries a verified
    id_token_hint for the signed-in user. The confirmation form submits to
    ``/oauth2/logout/confirm``, which is CSRF-protected.

    Form Data: see ``end_session`` for the parameter list.
    """
    return _handle_end_session(
        request, tenant_id, user, id_token_hint, client_id, post_logout_redirect_uri, state
    )


@router.post("/oauth2/logout/confirm", response_class=HTMLResponse)
def end_session_confirm(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict | None, Depends(get_current_user)],
):
    """End the session after the user confirmed on the confirmation page.

    Always lands on the signed-out page: the confirmation page is only shown
    when the RP's redirect target could not be verified.
    """
    if user:
        terminated = terminate_session(
            request, tenant_id, metadata=_audit_metadata(EndSessionRequest(), confirmed=True)
        )
        upstream = upstream_logout_response(
            request, tenant_id, terminated, return_to=SIGNED_OUT_PATH
        )
        if upstream is not None:
            return upstream
        if terminated.frontchannel_logout_urls:
            return frontchannel_logout_response(
                request, terminated.frontchannel_logout_urls, SIGNED_OUT_PATH
            )
    return RedirectResponse(url="/oauth2/logout/done", status_code=303)


@router.get(SIGNED_OUT_PATH, response_class=HTMLResponse)
def signed_out_page(
    request: Request,
    user: Annotated[dict | None, Depends(get_current_user)],
):
    """The page shown after an end_session request ended the session."""
    if user:
        # Still (or again) signed in: the page would be wrong.
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "oauth2_logout_done.html",
        {"nav": {}, "csp_nonce": get_csp_nonce(request)},
    )


def _handle_end_session(
    request: Request,
    tenant_id: str,
    user: dict | None,
    id_token_hint: str | None,
    client_id: str | None,
    post_logout_redirect_uri: str | None,
    state: str | None,
) -> Response:
    """Resolve an end_session request and end the session or ask first."""
    resolved = oidc_service.resolve_end_session_request(
        tenant_id=tenant_id,
        issuer=tenant_base_url(request),
        id_token_hint=id_token_hint,
        client_id=client_id,
        post_logout_redirect_uri=post_logout_redirect_uri,
    )

    verified_for_session = (
        resolved.problem is None
        and resolved.hint_subject is not None
        and (user is None or resolved.hint_matches(str(user["id"])))
    )

    if verified_for_session:
        target: str | None = None
        if resolved.post_logout_redirect_uri:
            target = resolved.post_logout_redirect_uri
            if state:
                separator = "&" if "?" in target else "?"
                target = f"{target}{separator}{urlencode({'state': state})}"
        frontchannel_logout_urls: list[str] = []
        if user:
            terminated = terminate_session(
                request,
                tenant_id,
                metadata=_audit_metadata(resolved, confirmed=False),
            )
            frontchannel_logout_urls = terminated.frontchannel_logout_urls
            upstream = upstream_logout_response(
                request, tenant_id, terminated, return_to=target or SIGNED_OUT_PATH
            )
            if upstream is not None:
                return upstream
        if target:
            if frontchannel_logout_urls:
                return frontchannel_logout_response(request, frontchannel_logout_urls, target)
            # Exact match against the client's registered post-logout redirect URIs,
            # backed by a verified id_token_hint for that client.
            # redirect-ok: registered post_logout_redirect_uri, verified id_token_hint
            return RedirectResponse(url=target, status_code=303)
        if frontchannel_logout_urls:
            return frontchannel_logout_response(request, frontchannel_logout_urls, SIGNED_OUT_PATH)
        return RedirectResponse(url="/oauth2/logout/done", status_code=303)

    if user is None:
        # Nobody to sign out, and nowhere verified to send them.
        return RedirectResponse(url="/oauth2/logout/done", status_code=303)

    problem = resolved.problem
    if problem is None and resolved.hint_subject is not None:
        # A valid hint, but for a different user than the one signed in.
        problem = "other_user"

    return templates.TemplateResponse(
        request,
        "oauth2_logout_confirm.html",
        {
            "user": user,
            "problem": problem,
            "nav": {},
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


def _audit_metadata(resolved: EndSessionRequest, *, confirmed: bool) -> dict:
    """``user_signed_out`` metadata for a logout requested by an RP."""
    metadata: dict = {
        "reason": "rp_initiated_logout",
        "confirmed_by_user": confirmed,
        "id_token_hint_verified": resolved.hint_claims is not None,
        "post_logout_redirect": resolved.post_logout_redirect_uri is not None,
    }
    if resolved.client:
        metadata["client_id"] = resolved.client["client_id"]
    return metadata
