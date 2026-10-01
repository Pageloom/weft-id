"""Pushed Authorization Requests (RFC 9126).

A confidential client sends its authorization request parameters straight to
WeftID (``POST /oauth2/par``, client authenticated) and receives a
``request_uri`` of the form ``urn:ietf:params:oauth:request_uri:<reference>``.
It then sends the browser to the authorization endpoint with only
``client_id`` and that ``request_uri``. The parameters never pass through the
browser, and they were sent by an authenticated client.

Rules:

- The reference is 32 random bytes; only its SHA-256 is stored.
- A pushed request is bound to the client that pushed it, works once (the row
  is deleted when redeemed), and expires after ``EXPIRES_IN`` seconds.
- When the redeemed request has to wait for a login, the router stores it
  again with :func:`store_for_resume` (the login window's lifetime, no audit
  event), so the request resumed after login is still a pushed request and a
  client that requires PAR is not refused on the way back.
"""

import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import database
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import ValidationError

logger = logging.getLogger(__name__)

# RFC 9126 section 2.2: the request_uri is a URN with this prefix.
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

# How long a pushed request_uri works (RFC 9126 section 2.2 suggests a short
# lifetime, 5 to 600 seconds).
EXPIRES_IN = 60

# The longest reference accepted on the way in (ours are 43 characters).
_MAX_REFERENCE_LENGTH = 128

INVALID_REQUEST_URI = "invalid_request_uri"


@dataclass(frozen=True)
class PushedRequest:
    """The PAR endpoint's answer (RFC 9126 section 2.2)."""

    request_uri: str
    expires_in: int


def is_pushed_request_uri(value: str | None) -> bool:
    """True when a ``request_uri`` names a pushed request rather than a URL."""
    return bool(value) and str(value).startswith(REQUEST_URI_PREFIX)


def _hash(reference: str) -> str:
    return hashlib.sha256(reference.encode("utf-8")).hexdigest()


def _store(
    tenant_id: str, client: dict, parameters: dict[str, str], lifetime: int
) -> tuple[str, str]:
    """Store a pushed request; returns ``(row id, request_uri)``."""
    reference = secrets.token_urlsafe(32)
    row = database.oauth2.create_pushed_request(
        tenant_id,
        tenant_id,
        client_id=str(client["id"]),
        reference_hash=_hash(reference),
        parameters=parameters,
        expires_at=datetime.now(UTC) + timedelta(seconds=lifetime),
    )
    return str(row["id"]), REQUEST_URI_PREFIX + reference


def push_authorization_request(
    tenant_id: str, client: dict, parameters: dict[str, str]
) -> PushedRequest:
    """Store an authenticated client's authorization request.

    Authorization: the client authenticated at the PAR endpoint; the router
    has already validated the parameters as the authorization endpoint would.

    Logs: ``oauth2_authorization_request_pushed`` (system actor; no user is
    involved yet).

    Args:
        tenant_id: Tenant ID
        client: The authenticated client (normal, confidential, active)
        parameters: Authorization parameter name -> value

    Returns:
        The ``request_uri`` and its lifetime in seconds
    """
    row_id, request_uri = _store(tenant_id, client, parameters, EXPIRES_IN)
    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oauth2_client",
        artifact_id=str(client["id"]),
        event_type="oauth2_authorization_request_pushed",
        metadata={
            "client_id": client["client_id"],
            "client_name": client.get("name"),
            "pushed_request_id": row_id,
            "scope": parameters.get("scope"),
        },
    )
    return PushedRequest(request_uri=request_uri, expires_in=EXPIRES_IN)


def store_for_resume(
    tenant_id: str, client: dict, parameters: dict[str, str], lifetime: int
) -> str:
    """Store a redeemed pushed request again while the user logs in.

    Authorization: none -- the parameters come from a pushed request this
    client redeemed a moment ago. No audit event: this is the same request
    continuing, not a new one.

    Returns:
        A new ``request_uri`` for the stashed authorize path
    """
    return _store(tenant_id, client, parameters, lifetime)[1]


def redeem_pushed_request(tenant_id: str, client: dict, request_uri: str) -> dict[str, str]:
    """Redeem a ``request_uri`` from the PAR endpoint at the authorization endpoint.

    Authorization: none -- the request was stored by an authenticated client;
    it is bound to that client, so the query ``client_id`` must name it.

    Returns:
        The pushed authorization parameters

    Raises:
        ValidationError: ``invalid_request_uri`` when the request_uri is
            unknown, expired, already used, or was pushed by another client
    """
    reference = request_uri[len(REQUEST_URI_PREFIX) :]
    parameters = None
    if 0 < len(reference) <= _MAX_REFERENCE_LENGTH:
        parameters = database.oauth2.consume_pushed_request(
            tenant_id, str(client["id"]), _hash(reference)
        )
    if parameters is None:
        logger.info(
            "Pushed request_uri refused for client %s: unknown, expired, or used",
            client.get("client_id"),
        )
        raise ValidationError(
            message="The request_uri is unknown, expired, or already used.",
            code=INVALID_REQUEST_URI,
        )
    return parameters
