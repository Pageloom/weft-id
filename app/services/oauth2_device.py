"""OAuth 2.0 Device Authorization Grant (RFC 8628).

A device that cannot show a browser (a CLI, a TV, an embedded tool) asks for a
device code and a short user code, tells the person to open ``/device`` on
another screen and type the user code, then polls the token endpoint until the
person approves or denies.

Like the rest of the OAuth2 flow services, the protocol functions take a
``tenant_id`` and an already-authenticated client or user, not a
``RequestingUser``: the device authorization and token endpoints authenticate
the client, and ``/device`` authenticates the user.

Design points:

- Only normal, active clients with ``device_grant_enabled`` may start the flow.
- The confirmation page is always shown. Remembered consent never skips it,
  because the person typing the code is the only check that they started the
  sign-in themselves (RFC 8628 section 5.4, remote phishing). Approving still
  records consent, so the app is listed under the user's authorized apps.
- Tokens issued from this grant are not tied to the approving browser session
  (no ``sid``): the device signed in, not the browser. Ending the browser
  session leaves the device signed in; deactivation and revocation still reach
  its tokens.
"""

from dataclasses import dataclass
from datetime import datetime

import database
import oauth2
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import ForbiddenError
from services.oidc import consent as consent_service
from services.oidc.claims import parse_scope

# Poll outcomes that map one-to-one onto RFC 8628 section 3.5 token errors.
AUTHORIZATION_PENDING = "authorization_pending"
SLOW_DOWN = "slow_down"
EXPIRED_TOKEN = "expired_token"
ACCESS_DENIED = "access_denied"
INVALID_GRANT = "invalid_grant"
APPROVED = "approved"


@dataclass(frozen=True)
class DeviceAuthorization:
    """What the device authorization endpoint returns (RFC 8628 section 3.2)."""

    device_code: str
    user_code: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class PendingRequest:
    """A device request waiting for the user's decision on ``/device``."""

    id: str
    client: dict
    scope: str | None
    user_code: str


@dataclass(frozen=True)
class PollResult:
    """The outcome of one poll. ``row`` is set only for ``APPROVED``."""

    outcome: str
    row: dict | None = None


def client_can_use_device_grant(client: dict) -> bool:
    """True for a normal, active client an admin opted into the grant."""
    return (
        client.get("client_type") == "normal"
        and bool(client.get("is_active", True))
        and bool(client.get("device_grant_enabled"))
    )


def start_device_authorization(
    tenant_id: str, client: dict, scope: str | None
) -> DeviceAuthorization:
    """Create a device authorization request for an authenticated client.

    Logs: ``oauth2_device_authorization_requested`` (system actor; no user is
    involved yet).

    Raises:
        ForbiddenError: ``unauthorized_client`` when the client may not use
            the grant
    """
    if not client_can_use_device_grant(client):
        raise ForbiddenError(
            "Client is not authorized for the device authorization grant",
            code="unauthorized_client",
        )

    # Expired requests are swept on the path that adds them, like codes.
    database.oauth2.cleanup_expired_device_codes(tenant_id)
    created = database.oauth2.create_device_code(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=str(client["id"]),
        scope=scope,
    )
    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oauth2_client",
        artifact_id=str(client["id"]),
        event_type="oauth2_device_authorization_requested",
        metadata={
            "client_id": client["client_id"],
            "client_name": client.get("name"),
            "device_request_id": created["id"],
            "scope": scope,
        },
    )
    return DeviceAuthorization(
        device_code=created["device_code"],
        user_code=oauth2.format_user_code(created["user_code"]),
        expires_in=int(oauth2.DEVICE_CODE_EXPIRY.total_seconds()),
        interval=int(created["poll_interval"]),
    )


def find_pending_request(tenant_id: str, user_code: str) -> PendingRequest | None:
    """Resolve what a person typed on ``/device`` to a live request.

    Returns None for a malformed, unknown, expired, or already decided code,
    and for a request whose client has since been deactivated or opted out.
    """
    normalized = oauth2.normalize_user_code(user_code)
    if normalized is None:
        return None
    row = database.oauth2.get_pending_by_user_code(tenant_id, normalized)
    if row is None:
        return None
    client = database.oauth2.get_client_by_id(tenant_id, str(row["client_id"]))
    if client is None or not client_can_use_device_grant(client):
        return None
    return PendingRequest(
        id=str(row["id"]),
        client=client,
        scope=row["scope"],
        user_code=oauth2.format_user_code(normalized),
    )


def decide_request(
    tenant_id: str,
    request: PendingRequest,
    user_id: str,
    *,
    approved: bool,
    auth_time: datetime | None,
) -> bool:
    """Record the user's approval or denial of a pending request.

    An approval also records consent for the requested scopes.

    Logs: ``oauth2_device_authorization_approved`` or
    ``oauth2_device_authorization_denied``.

    Returns:
        False when the request was no longer pending (decided elsewhere or
        expired); nothing is written then.
    """
    user_id = str(user_id)
    decided = database.oauth2.decide_device_code(
        tenant_id,
        request.id,
        approved=approved,
        user_id=user_id,
        auth_time=auth_time,
    )
    if decided is None:
        return False

    if approved:
        scopes = parse_scope(request.scope)
        consent_service.record_consent(tenant_id, request.client, user_id, scopes)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="oauth2_client",
        artifact_id=str(request.client["id"]),
        event_type=(
            "oauth2_device_authorization_approved"
            if approved
            else "oauth2_device_authorization_denied"
        ),
        metadata={
            "client_id": request.client["client_id"],
            "client_name": request.client.get("name"),
            "device_request_id": request.id,
            "scope": request.scope,
        },
    )
    return True


def poll(tenant_id: str, client: dict, device_code: str) -> PollResult:
    """Classify one token-endpoint poll (RFC 8628 section 3.5).

    A pending request records the poll and answers ``slow_down`` when it came
    too soon. An approved request is returned unredeemed: the caller re-checks
    access and then calls ``redeem``.
    """
    row = database.oauth2.find_device_code(tenant_id, device_code, str(client["id"]))
    if row is None or row["status"] == "redeemed":
        return PollResult(INVALID_GRANT)
    if row["expired"]:
        return PollResult(EXPIRED_TOKEN)
    if row["status"] == "denied":
        return PollResult(ACCESS_DENIED)
    if row["status"] == "approved":
        return PollResult(APPROVED, row)

    polled = database.oauth2.record_poll(tenant_id, str(row["id"]))
    if polled is not None and polled["slow_down"]:
        return PollResult(SLOW_DOWN)
    return PollResult(AUTHORIZATION_PENDING)


def redeem(tenant_id: str, client: dict, row: dict) -> dict | None:
    """Mark an approved request redeemed so tokens can be issued, once.

    Logs: ``oauth2_device_code_redeemed``.

    Returns:
        Dict with id (the grant id for the issued tokens), user_id, scope,
        auth_time; None when a concurrent poll redeemed it first or it expired
    """
    redeemed = database.oauth2.redeem_device_code(tenant_id, str(row["id"]))
    if redeemed is None:
        return None
    redeemed["id"] = str(redeemed["id"])
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(redeemed["user_id"]),
        artifact_type="oauth2_client",
        artifact_id=str(client["id"]),
        event_type="oauth2_device_code_redeemed",
        metadata={
            "client_id": client["client_id"],
            "client_name": client.get("name"),
            "device_request_id": redeemed["id"],
            "scope": redeemed["scope"],
        },
    )
    return redeemed
