"""Shared helpers for SAML IdP routers."""

from fastapi import Request


def get_base_url(request: Request) -> str:
    """Get base URL from request for building SAML URLs (always HTTPS)."""
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"
