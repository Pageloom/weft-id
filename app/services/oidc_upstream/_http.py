"""Shared settings for the connector's outbound HTTP calls.

Every call still goes through :func:`utils.safe_http.build_safe_client`; this
module only holds what all of them pass to it and how they read the response.
"""

from __future__ import annotations

from typing import Any

import httpx

# The OpenID Foundation conformance suite plays the upstream IdP in the RP
# conformance plans. It runs as a docker service on the dev network (a private
# address the SSRF guard would refuse). Dev only: inert when IS_DEV is false,
# and TLS verification is already off in dev through ``dev_base_domain_rewrite``.
DEV_HOSTNAME_ALLOWLIST = frozenset({"localhost.emobix.co.uk"})

# httpx timeouts apply per socket operation; TOTAL_TIMEOUT_SECONDS bounds the
# whole fetch (it is measured from client construction: one client per fetch).
FETCH_TIMEOUT_SECONDS = 10.0
TOTAL_TIMEOUT_SECONDS = 20.0

# Discovery documents, key sets, token and userinfo responses are a few KiB.
MAX_RESPONSE_BYTES = 1024 * 1024

# Keyword arguments every connector fetch passes to ``build_safe_client``.
# dev_base_domain_rewrite lets a dev-stack tenant act as its own upstream IdP
# (the loopback E2E); it is inert outside IS_DEV.
SAFE_CLIENT_OPTIONS: dict[str, Any] = {
    "timeout": FETCH_TIMEOUT_SECONDS,
    "total_timeout": TOTAL_TIMEOUT_SECONDS,
    "dev_base_domain_rewrite": True,
    "dev_hostname_allowlist": DEV_HOSTNAME_ALLOWLIST,
}


class ResponseTooLargeError(Exception):
    """The IdP's response body exceeded ``MAX_RESPONSE_BYTES``."""


def read_capped(client: httpx.Client, method: str, url: str, **kwargs: Any) -> tuple[int, bytes]:
    """Send one request and return ``(status, body)``, the body bounded in size.

    The body is read only for a 200; any other status returns ``b""``.

    Raises:
        ResponseTooLargeError: if the body exceeds ``MAX_RESPONSE_BYTES``.
    """
    with client.stream(method, url, **kwargs) as response:
        if response.status_code != 200:
            return response.status_code, b""
        body = b""
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > MAX_RESPONSE_BYTES:
                raise ResponseTooLargeError("response is too large")
    return response.status_code, body
