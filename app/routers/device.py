"""Device verification page for the OAuth 2.0 Device Authorization Grant (RFC 8628).

A device shows the user a short code and the ``/device`` URL. The user opens it
on a phone or computer, signs in, types the code, and approves or denies on a
confirmation page that names the application and what it asks for. The device,
polling the token endpoint, then receives its tokens or ``access_denied``.

The page is PUBLIC at the page-access layer and checks the session itself (like
the authorization endpoint): an anonymous visitor is sent to the login flow
with this page (and any ``user_code`` from the link) stashed, so login resumes
here instead of ending on the dashboard.
"""

import time
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlencode, urlparse

import oauth2
import services.oauth2_device as oauth2_device_service
import services.oidc as oidc_service
from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from middleware.csrf import make_csrf_token_func
from routers.saml_idp._helpers import PENDING_DEVICE_KEY
from services.exceptions import RateLimitError
from services.oauth2_device import PendingRequest
from services.oidc.claims import parse_scope
from utils.csp_nonce import get_csp_nonce
from utils.ratelimit import MINUTE, ratelimit
from utils.templates import templates

router = APIRouter(prefix="/device", tags=["device"], include_in_schema=False)

# Session key holding the request the confirmation page is showing. One-time:
# popped by the decision. Bound to the user who looked it up.
DEVICE_VERIFICATION_KEY = "device_verification"

# The confirmation page must be answered within this many seconds (the device
# code itself lives 10 minutes, and is re-checked on the decision anyway).
CONFIRM_MAX_AGE_SECONDS = 600

# Code entries per user before the page refuses for a while. A user code has
# about 34 bits, so this keeps guessing someone else's code hopeless.
ENTRY_RATE_LIMIT = 10
ENTRY_RATE_WINDOW = MINUTE * 15

INVALID_CODE_MESSAGE = (
    "That code is not valid or has expired. Check the code on your device and try again."
)


def _entry_page(
    request: Request,
    user: dict,
    *,
    user_code: str = "",
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    return templates.TemplateResponse(
        request,
        "device_entry.html",
        {
            "user": user,
            "user_code": user_code,
            "error": error,
            "nav": {},
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
        status_code=status_code,
    )


def _message_page(
    request: Request, user: dict, outcome: str, *, status_code: int = 200
) -> Response:
    """Render the end-of-flow page: ``approved``, ``denied``, ``no_access``,
    or ``expired``."""
    return templates.TemplateResponse(
        request,
        "device_done.html",
        {
            "user": user,
            "outcome": outcome,
            "nav": {},
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
        status_code=status_code,
    )


def _display_code(raw: str | None) -> str:
    """The prefill for the code field: the normalised code when the link
    carried a well-formed one, otherwise nothing (never echo arbitrary text)."""
    normalized = oauth2.normalize_user_code(raw or "")
    return oauth2.format_user_code(normalized) if normalized else ""


def _user_can_access(tenant_id: str, user: dict, pending: PendingRequest) -> bool:
    """Group-based access, OIDC-enabled clients only (as at the authorization
    endpoint). Plain OAuth2 clients are never gated. A denial is audited as
    ``oidc_access_denied`` by the access check."""
    client = pending.client
    if not client.get("oidc_enabled"):
        return True
    return oidc_service.user_can_access_client(
        tenant_id=tenant_id,
        user_id=str(user["id"]),
        client_uuid=str(client["id"]),
        client_id=client["client_id"],
        client_name=client.get("name"),
    )


@router.get("", response_class=HTMLResponse)
def device_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict | None, Depends(get_current_user)],
    user_code: Annotated[str | None, Query(max_length=50)] = None,
) -> Response:
    """Show the code entry form, prefilled from ``verification_uri_complete``.

    The prefilled code is never looked up on GET: the user still presses
    Continue, so a link someone else sent cannot jump straight to the
    confirmation page.
    """
    code = _display_code(user_code)
    if not user:
        # A server-built relative path; get_post_auth_redirect honours it.
        path = f"/device?{urlencode({'user_code': code})}" if code else "/device"
        request.session[PENDING_DEVICE_KEY] = path
        return RedirectResponse(url="/login", status_code=303)
    if user.get("force_profile_completion"):
        return RedirectResponse(url="/account/profile", status_code=303)
    return _entry_page(request, user, user_code=code)


@router.post("", response_class=HTMLResponse)
def device_submit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_current_user)],
    user_code: Annotated[str, Form(max_length=50)],
) -> Response:
    """Look up the entered code and show the confirmation page."""
    try:
        ratelimit.prevent(
            "device_user_code:user:{user_id}",
            limit=ENTRY_RATE_LIMIT,
            timespan=ENTRY_RATE_WINDOW,
            user_id=str(user["id"]),
        )
    except RateLimitError:
        return _entry_page(
            request,
            user,
            error="Too many attempts. Please wait a few minutes and try again.",
            status_code=429,
        )

    pending = oauth2_device_service.find_pending_request(tenant_id, user_code)
    if pending is None:
        return _entry_page(
            request, user, user_code=user_code[:20], error=INVALID_CODE_MESSAGE, status_code=400
        )
    if not _user_can_access(tenant_id, user, pending):
        return _message_page(request, user, "no_access", status_code=403)

    request.session[DEVICE_VERIFICATION_KEY] = {
        "id": pending.id,
        "user_code": pending.user_code,
        "user_id": str(user["id"]),
        "created_at": time.time(),
    }

    scopes = sorted(parse_scope(pending.scope))
    requested_scopes = [
        {"name": s, "description": oidc_service.SCOPE_DESCRIPTIONS.get(s, s)} for s in scopes
    ]

    # A registered logo (https, validated when set) loads from its own origin.
    if pending.client.get("logo_uri"):
        parts = urlparse(pending.client["logo_uri"])
        request.state.csp_img_src_origins = [f"{parts.scheme}://{parts.netloc}"]

    return templates.TemplateResponse(
        request,
        "device_confirm.html",
        {
            "user": user,
            "client": pending.client,
            "user_code": pending.user_code,
            "requested_scopes": requested_scopes,
            "nav": {},
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.post("/decision", response_class=HTMLResponse)
def device_decision(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_current_user)],
    action: Annotated[str, Form(max_length=20)],
) -> Response:
    """Approve or deny the request shown on the confirmation page."""
    stash = request.session.pop(DEVICE_VERIFICATION_KEY, None)
    if (
        not isinstance(stash, dict)
        or stash.get("user_id") != str(user["id"])
        or time.time() - float(stash.get("created_at") or 0) > CONFIRM_MAX_AGE_SECONDS
    ):
        return _message_page(request, user, "expired", status_code=400)

    # Re-resolve: the request may have expired or been decided in another tab.
    pending = oauth2_device_service.find_pending_request(tenant_id, str(stash["user_code"]))
    if pending is None or pending.id != stash.get("id"):
        return _message_page(request, user, "expired", status_code=400)

    if action == "deny":
        if not oauth2_device_service.decide_request(
            tenant_id, pending, str(user["id"]), approved=False, auth_time=None
        ):
            return _message_page(request, user, "expired", status_code=400)
        return _message_page(request, user, "denied")

    if action != "allow":
        return _message_page(request, user, "expired", status_code=400)

    # Defense in depth: membership may have changed since the code was entered.
    if not _user_can_access(tenant_id, user, pending):
        return _message_page(request, user, "no_access", status_code=403)

    # The ID token's auth_time is when this browser session authenticated.
    session_start = request.session.get("session_start")
    auth_time = (
        datetime.fromtimestamp(session_start, UTC)
        if isinstance(session_start, int | float)
        else datetime.now(UTC)
    )
    if not oauth2_device_service.decide_request(
        tenant_id, pending, str(user["id"]), approved=True, auth_time=auth_time
    ):
        return _message_page(request, user, "expired", status_code=400)
    return _message_page(request, user, "approved")
