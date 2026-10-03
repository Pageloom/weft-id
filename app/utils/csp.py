"""Content-Security-Policy source expressions built from stored URLs.

Some pages widen the policy with the origin of a URL that was registered by
a client or configured by an admin (a redirect URI, a logo, a logout URI, a
SAML endpoint). A header value must never carry anything but a plain source
expression, whatever the URL looks like: a space or semicolon in it would
start a new directive. Every such source goes through this module, both where
a router chooses it and again where the middleware writes the header.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# scheme://host[:port], the host a plain hostname, IPv4 or bracketed IPv6.
_ORIGIN = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]*://([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?"
)

# Characters that end a source expression or a directive.
_UNSAFE = re.compile(r"""[\s;,'"]""")


def csp_origin(url: str | None) -> str | None:
    """``scheme://host[:port]`` of ``url``, or None when that is not a plain origin."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    origin = f"{parts.scheme}://{parts.netloc}"
    return origin if _ORIGIN.fullmatch(origin) else None


def csp_source(url: str | None) -> str | None:
    """A source expression for ``url``: the URL itself when it can be written
    into a policy as it is, else its origin, else None."""
    origin = csp_origin(url)
    if origin is None or url is None:
        return None
    return origin if _UNSAFE.search(url) else url


def csp_origins(urls: list[str] | None) -> list[str]:
    """The distinct plain origins of ``urls``, in order."""
    origins: list[str] = []
    for url in urls or []:
        origin = csp_origin(url)
        if origin is not None and origin not in origins:
            origins.append(origin)
    return origins
