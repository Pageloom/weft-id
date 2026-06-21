"""SSRF-hardened httpx client for outbound server-side requests.

Any server-side HTTP request to a caller-supplied URL is an SSRF vector:
a hostname under attacker control can resolve (or, via DNS rebinding,
re-resolve) to a loopback / private / link-local / cloud-metadata
address. Validating the URL only at config-save time does not help,
because the request is dialed later against a fresh DNS lookup.

`build_safe_client()` returns an `httpx.Client` whose transport, on every
request:

1. Resolves the hostname once (or accepts a literal IP).
2. Rejects the request if *any* resolved address is in a blocked range,
   reusing the same blocklist as the SAML metadata fetcher
   (`utils.url_safety`).
3. Dials that exact validated IP -- the request URL host is rewritten to
   the IP literal so httpcore performs no second resolution (no
   resolve->connect TOCTOU). The original `Host` header is preserved for
   routing and the `sni_hostname` extension carries the real hostname so
   TLS SNI and certificate verification still run against it.

Redirect following is disabled: a 3xx to a private IP would otherwise be
followed without re-validation.

Two dev-only escape hatches keep local development working; both are inert
in production (`IS_DEV` is false):

- `dev_hostname_allowlist`: hostnames that resolve to private docker-bridge
  addresses and are intentionally permitted (e.g. the SCIM testbed).
- `dev_base_domain_rewrite`: when the target is a `*.BASE_DOMAIN` host,
  rewrite the connection to the `reverse-proxy` container (Host header
  preserved, TLS verification skipped), mirroring
  `utils.url_safety.fetch_metadata_xml`. Used by the SAML SLO back-channel,
  whose targets are tenant subdomains served by the dev reverse proxy.
"""

from __future__ import annotations

import socket

import httpx
import settings
from utils import url_safety

# Default per-request HTTP timeout for outbound calls that do not specify one.
_DEFAULT_TIMEOUT_SECONDS = 30.0

# Dev container hostname used by `dev_base_domain_rewrite`.
_DEV_REVERSE_PROXY_HOST = "reverse-proxy"


class SsrfBlockedError(httpx.ConnectError):
    """Raised when a target resolves to a blocked address.

    Subclasses `httpx.ConnectError` (an `httpx.RequestError`) so callers'
    existing request-error handling treats it as a network-level failure
    rather than letting it crash the caller.
    """


def _resolve_and_validate(host: str, port: int | None) -> str:
    """Resolve `host` and return a single validated IP to dial.

    Raises `SsrfBlockedError` if the hostname cannot be resolved or any
    resolved address falls in a blocked (private / loopback / link-local /
    reserved / metadata) range.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SsrfBlockedError(f"target hostname could not be resolved: {host}") from exc

    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        raw = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else None
        if not isinstance(raw, str) or not raw:
            continue
        # Strip an IPv6 zone identifier (`fe80::1%en0`) before validating.
        addr = raw.split("%", 1)[0]
        try:
            blocked = url_safety.is_blocked_ip(addr)
        except ValueError as exc:  # pragma: no cover - defensive
            raise SsrfBlockedError(f"target resolved to an unparseable address: {addr}") from exc
        if blocked:
            raise SsrfBlockedError("target resolves to a private or reserved address")
        addresses.append(addr)

    if not addresses:
        raise SsrfBlockedError(f"target hostname could not be resolved: {host}")

    # Every resolved address passed the blocklist; pin the first one.
    return addresses[0]


class PinnedResolveTransport(httpx.HTTPTransport):
    """httpx transport that validates and IP-pins each outbound request."""

    def __init__(
        self,
        *,
        dev_hostname_allowlist: frozenset[str] = frozenset(),
        dev_base_domain_rewrite: bool = False,
        verify: bool = True,
    ) -> None:
        super().__init__(verify=verify)
        self._dev_hostname_allowlist = dev_hostname_allowlist
        self._dev_base_domain_rewrite = dev_base_domain_rewrite

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host

        # Dev escape hatch: known docker service names that resolve to private
        # bridge addresses. Inert in production (IS_DEV is false).
        if settings.IS_DEV and host in self._dev_hostname_allowlist:
            return super().handle_request(request)

        # Dev escape hatch: *.BASE_DOMAIN tenant subdomains are served by the
        # dev reverse proxy and do not resolve to a routable IP inside the
        # container. Rewrite to the proxy container, preserving the Host
        # header for routing. TLS verification is already off on this client
        # (see build_safe_client). Inert in production.
        if settings.IS_DEV and self._dev_base_domain_rewrite and _is_base_domain_host(host):
            port = request.url.port or 443
            request.url = request.url.copy_with(host=_DEV_REVERSE_PROXY_HOST, port=port)
            return super().handle_request(request)

        pinned_ip = _resolve_and_validate(host, request.url.port)

        # Carry the real hostname into the TLS handshake (SNI + certificate
        # verification) before swapping the URL host to the pinned IP.
        request.extensions = {**request.extensions, "sni_hostname": host}
        # The `Host` header was set to the real hostname when the request was
        # built; rewriting the URL host to the IP literal does not touch it,
        # so routing on the receiver is preserved.
        request.url = request.url.copy_with(host=pinned_ip)

        return super().handle_request(request)


def _is_base_domain_host(host: str | None) -> bool:
    """Whether `host` is a subdomain of the configured BASE_DOMAIN (dev)."""
    base = settings.BASE_DOMAIN
    return bool(base and host and host.endswith(base))


def build_safe_client(
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    dev_hostname_allowlist: frozenset[str] = frozenset(),
    dev_base_domain_rewrite: bool = False,
) -> httpx.Client:
    """Build an `httpx.Client` hardened against SSRF.

    Args:
        timeout: Per-request timeout in seconds.
        dev_hostname_allowlist: Dev-only hostnames to dial without
            validation (docker service names). Inert in production.
        dev_base_domain_rewrite: Dev-only; route `*.BASE_DOMAIN` targets
            through the reverse-proxy container with TLS verification off.
            Inert in production.
    """
    # The dev reverse-proxy serves tenant subdomains with a local cert, so TLS
    # verification must be skipped when that rewrite is active. This only ever
    # loosens verification in dev; production keeps full verification.
    verify = not (settings.IS_DEV and dev_base_domain_rewrite)
    transport = PinnedResolveTransport(
        dev_hostname_allowlist=dev_hostname_allowlist,
        dev_base_domain_rewrite=dev_base_domain_rewrite,
        verify=verify,
    )
    return httpx.Client(  # ssrf-ok: this IS the guard (validates per request)
        timeout=timeout,
        follow_redirects=False,
        transport=transport,
    )
