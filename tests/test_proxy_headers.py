"""Regression guards for the reverse-proxy trust configuration.

`ProxyHeadersMiddleware` must be the OUTERMOST middleware so the real
client IP (from `X-Forwarded-For`) reaches every downstream layer --
most importantly the per-IP rate limiters. Starlette runs the
last-added middleware first, so the middleware registered at index 0 of
`user_middleware` is the outermost one. If a future change reorders the
middleware stack and pushes this inward, per-IP rate-limit buckets
silently collapse to a single global bucket behind the proxy.
"""

from __future__ import annotations

from main import app
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware


def test_proxy_headers_middleware_is_outermost():
    outermost = app.user_middleware[0]
    assert outermost.cls is ProxyHeadersMiddleware


def test_proxy_headers_trusts_configured_hosts():
    outermost = app.user_middleware[0]
    # Default trusts all immediate peers because the app is only
    # reachable through the proxy (its port is never published).
    assert outermost.kwargs.get("trusted_hosts") == "*"
