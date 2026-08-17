"""Redirect-target validation.

Single policy point for building redirect responses whose target is derived
from request data (path parameters, query parameters, session values).

This is deliberately separate from ``utils.url_safety``: that module guards
*outbound* fetches against SSRF, while this one guards *browser* redirects
against open-redirect and response-splitting. The two policies share no rules
and conflating them would make both harder to reason about.

Two shapes are supported:

``safe_redirect()``
    Same-origin redirects. The target must be a relative path rooted at ``/``.
    This covers the overwhelming majority of redirects in the app.

``safe_external_redirect()``
    Cross-origin redirects that are legitimate by design (the forward-auth
    handshake hops between a tenant's canonical host and a protected domain's
    portal host). The host must appear in a caller-supplied allowlist that was
    resolved from the tenant's own registered domains.
"""

from urllib.parse import urlsplit

from fastapi.responses import RedirectResponse

# Redirect targets are internal paths, not documents. Anything longer than this
# is a malformed or hostile value rather than a route we serve.
MAX_TARGET_LEN = 2048

# Fallback when a caller does not supply one. Every authenticated surface in the
# app can reach the dashboard, so it is always a valid landing place.
DEFAULT_TARGET = "/dashboard"


def is_safe_path(target: str | None) -> bool:
    """Whether ``target`` is a safe same-origin relative path.

    A target is safe only when every one of these holds:

    * it is a non-empty string within ``MAX_TARGET_LEN``
    * it is rooted at ``/`` (relative to our own origin)
    * it is not protocol-relative (``//evil.com`` loads another origin)
    * it carries no scheme (``://``, or a bare ``javascript:``/``data:``)
    * it contains no backslash, which browsers fold into ``/`` before
      resolving, so ``/\\evil.com`` is protocol-relative in practice
    * it contains no control characters, which can split the ``Location``
      header and inject a second response
    """
    if not target or not isinstance(target, str):
        return False
    if len(target) > MAX_TARGET_LEN:
        return False
    if not target.startswith("/"):
        return False
    if target.startswith("//"):
        return False
    if "\\" in target:
        return False
    if any(ch < " " or ch == "\x7f" for ch in target):
        return False
    # A scheme cannot appear in a path rooted at "/", so any scheme separator
    # means the value is trying to escape the origin.
    if "://" in target:
        return False
    # urlsplit resolves percent-encoded and mixed-case tricks that a literal
    # substring check misses (e.g. "/%2f/evil.com" or "JaVaScRiPt:alert(1)").
    parts = urlsplit(target)
    return not (parts.scheme or parts.netloc)


def safe_path(target: str | None, default: str = DEFAULT_TARGET) -> str:
    """Return ``target`` when it is a safe relative path, else ``default``.

    Falls back silently rather than raising: a hostile or stale redirect target
    should land the user somewhere sensible, not on an error page.
    """
    if is_safe_path(target):
        # Narrowed by is_safe_path, which rejects None and non-str.
        return str(target)
    return default


def safe_redirect(
    target: str | None,
    default: str = DEFAULT_TARGET,
    status_code: int = 303,
) -> RedirectResponse:
    """Build a ``RedirectResponse`` to a validated same-origin path.

    Args:
        target: Candidate path, typically built from request data.
        default: Where to send the user when ``target`` fails validation.
        status_code: 303 for post-form redirects, 302 for interstitial hops.
    """
    return RedirectResponse(url=safe_path(target, default), status_code=status_code)


def safe_external_redirect(
    host: str,
    path: str,
    allowed_hosts: set[str] | frozenset[str],
    status_code: int = 302,
) -> RedirectResponse | None:
    """Build a cross-origin ``RedirectResponse`` to an allowlisted host.

    Returns ``None`` when the host is not allowlisted or the path is unsafe, so
    the caller must decide how to fail. Callers fail closed with a denial page
    rather than falling back to a default origin, because a cross-origin hop
    that cannot be verified has no safe substitute.

    Args:
        host: Target hostname, normalized by the caller.
        path: Same-origin-style path on that host, rooted at ``/``.
        allowed_hosts: Hosts resolved from the tenant's registered domains.
        status_code: 302 for handshake hops.
    """
    if not host or host not in allowed_hosts:
        return None
    if not is_safe_path(path):
        return None
    return RedirectResponse(url=f"https://{host}{path}", status_code=status_code)
