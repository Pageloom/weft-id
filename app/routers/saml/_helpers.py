"""Shared helper functions for SAML router modules."""

import base64

from fastapi import Request, Response
from services import saml as saml_service
from settings import IS_DEV
from utils.csp_nonce import get_csp_nonce
from utils.templates import templates


def get_base_url(request: Request) -> str:
    """Get the base URL for the request (always HTTPS)."""
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"


def decode_saml_response_for_debug(saml_response: str) -> str | None:
    """Safely decode a base64 SAML response for debug display.

    Returns None if decoding fails.
    """
    try:
        return base64.b64decode(saml_response).decode("utf-8")
    except Exception:
        return None


def store_saml_debug_and_respond(
    request: Request,
    tenant_id: str,
    error_type: str,
    error_detail: str | None,
    saml_response_b64: str | None,
    idp_id: str | None = None,
    idp_name: str | None = None,
    verbose_event_logging: bool = False,
) -> Response:
    """
    Store a SAML debug entry and return an error template response.

    This is a helper that:
    1. Stores the debug entry for super admin review
    2. Optionally logs a verbose assertion failure event
    3. Returns the appropriate error page to the user
    """
    # Get request metadata for debug entry
    request_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Store debug entry
    saml_service.store_saml_debug_entry(
        tenant_id=tenant_id,
        error_type=error_type,
        error_detail=error_detail,
        idp_id=idp_id,
        idp_name=idp_name,
        saml_response_b64=saml_response_b64,
        request_ip=request_ip,
        user_agent=user_agent,
        verbose_event_logging=verbose_event_logging,
    )

    # Decode XML for display in dev mode
    raw_saml_xml = None
    if IS_DEV and saml_response_b64:
        raw_saml_xml = decode_saml_response_for_debug(saml_response_b64)

    return templates.TemplateResponse(
        request,
        "saml_error.html",
        {
            "error_type": error_type,
            "is_dev": IS_DEV,
            "raw_saml_xml": raw_saml_xml,
            "csp_nonce": get_csp_nonce(request),
        },
    )
