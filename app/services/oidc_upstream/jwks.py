"""OIDC upstream JWKS fetching and caching.

Fetches the IdP's JSON Web Key Set through the SSRF guard and caches it per
connection with a TTL (~1 hour). The cache is refreshed once on a signature
verification failure (key rotation) and is never fetched per request.

PyJWT's ``PyJWKClient`` is *not* used here because it performs its own
``urllib`` fetch (bypassing the SSRF guard) and its cache is process-global
rather than per-connection. Instead we fetch the JWKS ourselves through
:func:`utils.safe_http.build_safe_client` and hand the parsed
``jwt.PyJWKSet`` to ``jwt.decode`` for verification.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta

import jwt
from services.oidc_upstream.errors import JwksError
from utils.safe_http import build_safe_client

logger = logging.getLogger(__name__)

# How long a fetched JWKS is considered fresh before a refetch is allowed.
_JWKS_TTL = timedelta(hours=1)

# A lock guarding the module-level cache (dict mutation is not atomic across
# the read-check-write in get_jwks).
_cache_lock = threading.Lock()

# Module-level cache: (tenant_id, connection_id) -> (fetched_at, jwks_dict).
# Stale entries are evicted on read (see ``_cached``) so the cache does not
# accumulate unboundedly.
_jwks_cache: dict[tuple[str, str], tuple[datetime, dict]] = {}


def _cache_key(tenant_id: str, connection_id: str) -> tuple[str, str]:
    return (tenant_id, connection_id)


def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch and parse a JWKS document through the SSRF guard.

    Raises:
        JwksError: on any fetch/parse failure.
    """
    with build_safe_client(timeout=10.0) as client:
        try:
            response = client.get(jwks_uri)
        except Exception as exc:  # noqa: BLE001
            raise JwksError(f"Failed to fetch JWKS: {exc}") from exc

    if response.status_code != 200:
        raise JwksError(f"JWKS fetch returned HTTP {response.status_code}")

    try:
        doc = response.json()
    except Exception as exc:  # noqa: BLE001
        raise JwksError(f"JWKS is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise JwksError("JWKS document is missing a 'keys' array")

    return doc


def _cached(tenant_id: str, connection_id: str) -> dict | None:
    """Return a cached JWKS dict if present and fresh, else None.

    Stale entries are evicted (popped) so the cache does not accumulate
    unboundedly.
    """
    key = _cache_key(tenant_id, connection_id)
    with _cache_lock:
        entry = _jwks_cache.get(key)
        if entry is None:
            return None
        fetched_at, doc = entry
        if datetime.now(UTC) - fetched_at >= _JWKS_TTL:
            _jwks_cache.pop(key, None)
            return None
        return doc


def _store(tenant_id: str, connection_id: str, doc: dict) -> None:
    with _cache_lock:
        _jwks_cache[_cache_key(tenant_id, connection_id)] = (datetime.now(UTC), doc)


def _invalidate(tenant_id: str, connection_id: str) -> None:
    with _cache_lock:
        _jwks_cache.pop(_cache_key(tenant_id, connection_id), None)


def get_jwks(tenant_id: str, connection_id: str, jwks_uri: str) -> jwt.PyJWKSet:
    """Return the parsed JWKS for a connection, using the cache when fresh.

    Args:
        tenant_id: Tenant ID (cache namespace).
        connection_id: Connection ID (cache namespace).
        jwks_uri: The JWKS endpoint URL (from the connection row).

    Returns:
        A ``jwt.PyJWKSet`` ready for ``jwt.decode``.

    Raises:
        JwksError: if the JWKS cannot be fetched or parsed.
    """
    doc = _cached(tenant_id, connection_id)
    if doc is None:
        doc = _fetch_jwks(jwks_uri)
        _store(tenant_id, connection_id, doc)

    try:
        return jwt.PyJWKSet.from_dict(doc)
    except Exception as exc:  # noqa: BLE001
        raise JwksError(f"Failed to parse JWKS: {exc}") from exc


def refresh_jwks(tenant_id: str, connection_id: str, jwks_uri: str) -> jwt.PyJWKSet:
    """Force a refetch of the JWKS (used on signature-verification failure).

    Invalidates the cache entry, refetches, and returns the fresh key set.
    """
    _invalidate(tenant_id, connection_id)
    return get_jwks(tenant_id, connection_id, jwks_uri)


def clear_jwks_cache(tenant_id: str, connection_id: str) -> None:
    """Drop the cached JWKS for a connection (e.g. on connection delete)."""
    _invalidate(tenant_id, connection_id)
