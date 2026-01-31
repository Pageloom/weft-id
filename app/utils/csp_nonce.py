"""CSP nonce generation for Content Security Policy.

This module provides per-request nonce generation for CSP headers.
Nonces are stored in request.state and used in both:
1. The CSP header (script-src 'nonce-{value}')
2. Inline script tags (nonce="{value}")

No database persistence is needed. Nonces are stateless and per-request.
"""

import secrets

from starlette.requests import Request


def generate_csp_nonce() -> str:
    """Generate a cryptographically secure CSP nonce.

    Returns a URL-safe base64-encoded 32-byte random value.
    """
    return secrets.token_urlsafe(32)


def get_csp_nonce(request: Request) -> str:
    """Get or create CSP nonce from request.state.

    This function is idempotent. Multiple calls with the same request
    return the same nonce value.

    Args:
        request: The current request object

    Returns:
        The CSP nonce string for this request
    """
    if not hasattr(request.state, "csp_nonce"):
        request.state.csp_nonce = generate_csp_nonce()
    nonce: str = request.state.csp_nonce
    return nonce
