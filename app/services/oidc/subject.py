"""Subject identifiers: the ``sub`` a client knows a user by.

OpenID Connect Core 1.0 section 8 defines two subject identifier types:

* ``public`` (the default): ``sub`` is the stable WeftID user id, the same at
  every client.
* ``pairwise`` (a per-client opt-in): ``sub`` is derived from the user id and
  the client's **sector**, so clients in different sectors cannot correlate a
  user by ``sub``. Clients in the same sector see the same value.

The sector is the host of the client's ``sector_identifier_uri`` when it has
one, otherwise the host of its redirect URIs (which must then all share one
host, Core 8.1). A sector identifier URI serves a JSON array of URIs that must
include every redirect URI of the client; that is checked when the setting is
made (dynamic registration, admin change, redirect URI edit), not at login.

Every place WeftID emits a ``sub`` to a client goes through
:func:`subject_for`: ID tokens, userinfo, token introspection, back-channel
logout tokens, and the ``id_token_hint`` checks that compare a ``sub`` the
client presents with the signed-in user.

The pairwise value is ``base64url(HMAC-SHA256(key, sector || 0x00 || user_id))``
with a key derived from ``SECRET_KEY`` (HKDF, its own purpose label). It is
deterministic, so nothing is stored, and it cannot be reversed without the key.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
from urllib.parse import urlsplit

import database
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.crypto import derive_hmac_key
from utils.fetch_guard import FetchGuard
from utils.safe_http import build_safe_client
from utils.url_safety import has_plain_authority

PUBLIC = "public"
PAIRWISE = "pairwise"
SUBJECT_TYPES = (PUBLIC, PAIRWISE)

INVALID_SUBJECT_TYPE = "invalid_subject_type"
INVALID_SECTOR_IDENTIFIER_URI = "invalid_sector_identifier_uri"

MAX_SECTOR_DOCUMENT_BYTES = 32768
MAX_URI_LENGTH = 2048
_FETCH_TIMEOUT_SECONDS = 5.0

# The OIDC conformance suite serves sector documents from a docker service on
# the dev network with a self-signed certificate. Dev only, as for jwks_uri.
_DEV_HOSTNAME_ALLOWLIST = frozenset({"localhost.emobix.co.uk"})

# Per sector URI (registration has no client yet): a failing document is not
# refetched for 30s, and one fetch runs at a time.
_sector_fetch_guard = FetchGuard()


@functools.cache
def _pairwise_key() -> bytes:
    return derive_hmac_key("oidc-pairwise-subject")


def _host(uri: str) -> str | None:
    try:
        return urlsplit(uri).hostname
    except ValueError:
        return None


def sector_host(client: dict) -> str | None:
    """The client's sector: its sector identifier URI's host, else the host of
    its redirect URIs. None when neither gives one (never for a client whose
    pairwise setting was validated)."""
    sector_uri = client.get("sector_identifier_uri")
    if sector_uri:
        return _host(sector_uri)
    hosts = {_host(uri) for uri in client.get("redirect_uris") or []}
    hosts.discard(None)
    return hosts.pop() if len(hosts) == 1 else None


def pairwise_subject(sector: str, user_id: str) -> str:
    """The pairwise ``sub`` of a user in a sector (43 URL-safe characters)."""
    digest = hmac.new(_pairwise_key(), f"{sector}\x00{user_id}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def subject_for(client: dict, user_id: str) -> str:
    """The ``sub`` the client knows this user by.

    Args:
        client: The client row; reads ``subject_type``,
            ``sector_identifier_uri`` and ``redirect_uris``.
        user_id: The WeftID user id.

    Raises:
        ValueError: a pairwise client with no determinable sector. Saving the
            setting validates the sector, so this means the row was changed
            outside the service layer; failing beats leaking the public id.
    """
    if client.get("subject_type") != PAIRWISE:
        return str(user_id)
    sector = sector_host(client)
    if sector is None:
        raise ValueError("pairwise client has no sector")
    return pairwise_subject(sector, str(user_id))


def subject_matches(client: dict, user_id: str, sub: object) -> bool:
    """Whether a ``sub`` the client presented (an ``id_token_hint``) is this user."""
    return isinstance(sub, str) and hmac.compare_digest(subject_for(client, user_id), sub)


# =============================================================================
# Validation
# =============================================================================


def _sector_error(message: str) -> ValidationError:
    return ValidationError(message=message, code=INVALID_SECTOR_IDENTIFIER_URI)


def _fetch_sector_document(sector_identifier_uri: str) -> list[str]:
    """Fetch the sector document through the SSRF guard: a JSON array of URIs."""
    http = build_safe_client(
        timeout=_FETCH_TIMEOUT_SECONDS,
        total_timeout=_FETCH_TIMEOUT_SECONDS * 2,
        dev_hostname_allowlist=_DEV_HOSTNAME_ALLOWLIST,
        dev_skip_tls_verify=True,
        dev_base_domain_rewrite=True,
    )
    try:
        with http, http.stream("GET", sector_identifier_uri) as response:
            if response.status_code != 200:
                raise _sector_error(
                    f"The sector identifier URI returned HTTP {response.status_code}"
                )
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_SECTOR_DOCUMENT_BYTES:
                    raise _sector_error("The sector identifier document is too large")
    except ValidationError:
        raise
    except Exception as exc:  # noqa: BLE001 - any transport failure is a refusal
        raise _sector_error(
            f"The sector identifier URI could not be retrieved ({type(exc).__name__})"
        ) from exc
    try:
        document = json.loads(body)
    except ValueError as exc:
        raise _sector_error("The sector identifier document is not JSON") from exc
    if not isinstance(document, list) or not all(isinstance(v, str) for v in document):
        raise _sector_error("The sector identifier document must be a JSON array of URIs")
    return document


def _validate_sector_identifier_uri(value: str) -> str:
    cleaned = value.strip()
    try:
        parts = urlsplit(cleaned)
        host = parts.hostname
    except ValueError:
        parts, host = None, None
    if (
        parts is None
        or len(cleaned) > MAX_URI_LENGTH
        or parts.scheme != "https"
        or not host
        or not has_plain_authority(parts)
        or parts.fragment
        or "#" in cleaned
    ):
        raise _sector_error("The sector identifier URI must be an absolute https URI")
    return cleaned


def validate_subject_settings(
    subject_type: str | None,
    sector_identifier_uri: str | None,
    redirect_uris: list[str],
) -> tuple[str, str | None]:
    """Check a client's subject settings against its redirect URIs.

    A ``public`` client takes no sector identifier URI. A ``pairwise`` client
    either has one, whose document (fetched now) lists every redirect URI, or
    redirect URIs that all share one host (Core 8.1). A pairwise client with
    no redirect URIs (a device client) needs a sector identifier URI.

    Returns:
        ``(subject_type, sector_identifier_uri)``, normalised (blank is None).

    Raises:
        ValidationError: code ``invalid_subject_type`` or
            ``invalid_sector_identifier_uri``.
    """
    subject_type = subject_type or PUBLIC
    if subject_type not in SUBJECT_TYPES:
        raise ValidationError(
            message=f"Unsupported subject_type. Supported: {', '.join(SUBJECT_TYPES)}",
            code=INVALID_SUBJECT_TYPE,
        )
    sector_uri = (sector_identifier_uri or "").strip() or None
    if subject_type == PUBLIC:
        if sector_uri is not None:
            raise _sector_error("A sector identifier URI is only used with pairwise subjects")
        return PUBLIC, None

    if sector_uri is not None:
        sector_uri = _validate_sector_identifier_uri(sector_uri)
        listed = set(
            _sector_fetch_guard.run(
                sector_uri,
                sector_uri,
                lambda: _fetch_sector_document(sector_uri),
                busy=lambda: _sector_error(
                    "The sector identifier URI is already being retrieved. Try again shortly."
                ),
            )
        )
        missing = [uri for uri in redirect_uris if uri not in listed]
        if missing:
            raise _sector_error(
                "The sector identifier document does not list every redirect URI "
                f"(missing: {', '.join(missing)[:200]})"
            )
        return PAIRWISE, sector_uri

    hosts = {_host(uri) for uri in redirect_uris}
    if not redirect_uris or None in hosts or len(hosts) != 1:
        raise _sector_error(
            "Pairwise subjects need a sector identifier URI unless all redirect URIs share one host"
        )
    return PAIRWISE, None


# =============================================================================
# Admin
# =============================================================================


def set_client_subject_type(
    requesting_user: RequestingUser,
    client_id: str,
    *,
    subject_type: str,
    sector_identifier_uri: str | None = None,
) -> dict:
    """Set whether an app receives public or pairwise subject identifiers.

    Changing it changes the ``sub`` of every user at the app, so the app
    treats them as new users unless it links accounts by other means.

    Authorization: Requires admin role.
    Logs: oauth2_client_subject_type_changed (only when something changed).

    Returns:
        The updated client dict.

    Raises:
        NotFoundError: No such normal client
        ForbiddenError: Insufficient role
        ValidationError: An invalid subject type or sector (see
            :func:`validate_subject_settings`)
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    old = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if old is None or old["client_type"] != "normal":
        raise NotFoundError(message="Client not found", code="oauth2_client_not_found")

    subject_type, sector_uri = validate_subject_settings(
        subject_type, sector_identifier_uri, list(old.get("redirect_uris") or [])
    )
    previous_type = old.get("subject_type") or PUBLIC
    if subject_type == previous_type and sector_uri == old.get("sector_identifier_uri"):
        return old

    updated = database.oauth2.set_client_subject_type(
        tenant_id, client_id, subject_type=subject_type, sector_identifier_uri=sector_uri
    )
    if updated is None:
        raise NotFoundError(message="Client not found", code="oauth2_client_not_found")

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oauth2_client",
        artifact_id=str(updated["id"]),
        event_type="oauth2_client_subject_type_changed",
        metadata={
            "name": updated["name"],
            "client_id": client_id,
            "subject_type": subject_type,
            "previous_subject_type": previous_type,
            "sector_identifier_uri": sector_uri,
            "previous_sector_identifier_uri": old.get("sector_identifier_uri"),
        },
    )
    return updated
