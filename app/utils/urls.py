"""URL construction helpers.

Centralises the recipe for "the tenant-facing base URL of this request"
so that any code building absolute URLs to surface to external systems
(SCIM `meta.location`, the admin SCIM-base copy block, etc.) derives the
host from one trusted place.

Trust boundary: `x-forwarded-host` is only safe because the reverse
proxy sets it authoritatively (nginx `proxy_set_header X-Forwarded-Host
$host`, Caddy by default), overwriting anything a client tried to inject.
A request that reaches uvicorn without going through the proxy cannot
happen in a real deployment -- the app port is never published directly
-- so the header is proxy-controlled. Falling back to
`request.url.netloc` keeps direct dev access (no proxy) working.
"""

from __future__ import annotations

from fastapi import Request


def tenant_base_url(request: Request) -> str:
    """Return the canonical `https://<tenant-host>` base for this request.

    Honours the proxy-set `x-forwarded-host` so absolute URLs we surface
    to external systems (Okta, Entra) point at the tenant subdomain
    operators actually see, not the pod-internal host. This is the single
    trusted host-derivation point; callers must not read the raw header
    themselves.
    """
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"
