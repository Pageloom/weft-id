"""OIDC upstream discovery.

Fetches and validates an IdP's OpenID Connect discovery document
(``/.well-known/openid-configuration``) and persists the four endpoints plus
the issuer on the connection row. This is the relying-party mirror of
``services.oidc.discovery`` (which *assembles* the document for downstream
RPs); here we *consume* it.

Security (cross-cutting requirement 1 -- SSRF):

- The fetch goes through :func:`utils.safe_http.build_safe_client`, which
  validates and IP-pins the target on every request. No bare ``httpx``.
- Redirects are not followed (``follow_redirects=False``); a discovery URL
  that redirects is rejected with a distinct error rather than looking like
  a network fault.
- The document's ``issuer`` must equal the connection's configured issuer.
- Every endpoint URL must be ``https`` (except in ``IS_DEV``, where ``http``
  is permitted for local development).

A document failing either check is rejected and recorded as an error, never
persisted. On a fetch/parse failure the prior endpoint values are left
intact and only ``discovery_error`` is written.

Refetch is TTL-gated per connection (not per request): a successful fetch
within the TTL is a no-op.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import database
import settings
from services.oidc_upstream.errors import (
    DiscoveryError,
    DiscoveryInsecureEndpointError,
    DiscoveryIssuerMismatchError,
    DiscoveryRedirectError,
)
from utils.safe_http import build_safe_client

logger = logging.getLogger(__name__)

# How long a successful discovery result is considered fresh. Refetches
# within this window are skipped (per-connection TTL, not per-request).
_DISCOVERY_TTL = timedelta(hours=1)

# The required endpoint fields we read out of the discovery document and
# persist. ``userinfo_endpoint`` is RECOMMENDED, not REQUIRED, per OIDC
# Discovery 1.0, so it is handled separately (optional).
_REQUIRED_ENDPOINT_FIELDS = (
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
)

# Optional endpoint fields: validated only if present, persisted as None when
# absent.
_OPTIONAL_ENDPOINT_FIELDS = ("userinfo_endpoint",)

# The well-known path appended to an issuer when no explicit discovery URL
# is configured.
_WELL_KNOWN_PATH = "/.well-known/openid-configuration"


def _require_https(url: str, field: str) -> None:
    """Reject a non-https endpoint URL (http allowed only in IS_DEV)."""
    scheme = urlparse(url).scheme.lower()
    if scheme == "https":
        return
    if scheme == "http" and settings.IS_DEV:
        return
    raise DiscoveryInsecureEndpointError(field, url)


def _validate_discovery_document(
    doc: dict,
    *,
    configured_issuer: str,
) -> dict[str, str | None]:
    """Validate a parsed discovery document and return the endpoint map.

    Raises:
        DiscoveryIssuerMismatchError: if the document issuer differs from the
            configured issuer.
        DiscoveryInsecureEndpointError: if any endpoint is not https (outside
            IS_DEV).
        DiscoveryError: if a required field is missing or not a string.
    """
    discovered_issuer = doc.get("issuer")
    if not isinstance(discovered_issuer, str) or not discovered_issuer:
        raise DiscoveryError("Discovery document missing 'issuer'")

    # The issuer must match exactly (trailing-slash normalized) so a document
    # served from a different authority cannot be accepted.
    if discovered_issuer.rstrip("/") != configured_issuer.rstrip("/"):
        raise DiscoveryIssuerMismatchError(configured_issuer, discovered_issuer)

    endpoints: dict[str, str | None] = {}
    for field in _REQUIRED_ENDPOINT_FIELDS:
        value = doc.get(field)
        if not isinstance(value, str) or not value:
            raise DiscoveryError(f"Discovery document missing '{field}'")
        _require_https(value, field)
        endpoints[field] = value

    for field in _OPTIONAL_ENDPOINT_FIELDS:
        value = doc.get(field)
        if value is None:
            endpoints[field] = None
            continue
        if not isinstance(value, str) or not value:
            raise DiscoveryError(f"Discovery document has invalid '{field}'")
        _require_https(value, field)
        endpoints[field] = value

    return endpoints


def _fetch_discovery_document(discovery_url: str) -> dict:
    """Fetch and parse a discovery document through the SSRF guard.

    Raises:
        DiscoveryRedirectError: if the URL returns a 3xx (redirects are not
            followed).
        DiscoveryError: on any other fetch/parse failure.
    """
    with build_safe_client(timeout=10.0) as client:
        try:
            response = client.get(discovery_url)
        except Exception as exc:  # noqa: BLE001 - surface as DiscoveryError
            raise DiscoveryError(f"Failed to fetch discovery document: {exc}") from exc

    if 300 <= response.status_code < 400:
        raise DiscoveryRedirectError(discovery_url, response.status_code)

    if response.status_code != 200:
        raise DiscoveryError(f"Discovery fetch returned HTTP {response.status_code}")

    try:
        doc = response.json()
    except Exception as exc:  # noqa: BLE001
        raise DiscoveryError(f"Discovery document is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise DiscoveryError("Discovery document is not a JSON object")

    return doc


def _resolve_discovery_url(connection: dict) -> str:
    """Return the discovery URL to fetch for a connection.

    Prefers the explicit ``discovery_url``; falls back to the issuer's
    well-known path.
    """
    if connection.get("discovery_url"):
        return str(connection["discovery_url"])
    return f"{str(connection['issuer']).rstrip('/')}{_WELL_KNOWN_PATH}"


def _is_fresh(connection: dict) -> bool:
    """Whether the connection's discovery result is within the TTL."""
    fetched_at = connection.get("discovery_fetched_at")
    if fetched_at is None:
        return False
    if isinstance(fetched_at, str):
        return False
    return bool(datetime.now(UTC) - fetched_at < _DISCOVERY_TTL)


def run_discovery(tenant_id: str, connection_id: str, *, force: bool = False) -> dict:
    """Fetch and persist discovery for a connection.

    Args:
        tenant_id: Tenant ID for RLS scoping.
        connection_id: The connection to discover.
        force: Ignore the TTL and refetch even if the result is fresh.

    Returns:
        The updated connection row (dict).

    Raises:
        DiscoveryError (and subclasses) on failure. On failure the prior
        endpoint values are left intact and ``discovery_error`` is written.
    """
    connection = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if connection is None:
        raise DiscoveryError(f"OIDC connection not found: {connection_id}")

    if not force and _is_fresh(connection):
        return connection

    discovery_url = _resolve_discovery_url(connection)

    # The discovery URL itself is admin-supplied (or issuer-derived) and must
    # be https too, not just the endpoints inside the document.
    _require_https(discovery_url, "discovery_url")

    try:
        doc = _fetch_discovery_document(discovery_url)
        endpoints = _validate_discovery_document(
            doc,
            configured_issuer=connection["issuer"],
        )
    except DiscoveryError as exc:
        # Record the error but leave prior endpoint values intact.
        database.oidc_upstream.update_connection(
            tenant_id,
            connection_id,
            discovery_error=str(exc)[:10000],
        )
        raise

    row = database.oidc_upstream.update_connection(
        tenant_id,
        connection_id,
        authorization_endpoint=endpoints["authorization_endpoint"],
        token_endpoint=endpoints["token_endpoint"],
        userinfo_endpoint=endpoints["userinfo_endpoint"],
        jwks_uri=endpoints["jwks_uri"],
        discovery_fetched_at=datetime.now(UTC),
        discovery_error=None,
    )

    if row is None:
        raise DiscoveryError("Failed to persist discovery result")

    return row
