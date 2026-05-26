"""URL construction helpers.

Centralises the recipe for "the tenant-facing base URL of this request"
so that any code building absolute URLs to surface to external systems
(SCIM `meta.location`, the admin SCIM-base copy block, etc.) honours
`x-forwarded-host` consistently.

Behind nginx, `request.url.netloc` is the pod-internal host. The real
outward-facing host arrives in `x-forwarded-host` -- the same header
the SAML routers already trust. Falling back to `request.url.netloc`
keeps direct dev access working.
"""

from __future__ import annotations

from fastapi import Request


def tenant_base_url(request: Request) -> str:
    """Return the canonical `https://<tenant-host>` base for this request.

    Honours `x-forwarded-host` (set by the reverse proxy) so absolute
    URLs we surface to external systems (Okta, Entra) point at the
    tenant subdomain operators actually see, not the pod-internal host.
    """
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"
