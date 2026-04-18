"""WebAuthn (passkey) service layer.

Business logic for passkey registration, listing, renaming, and deletion.
Authentication (login with a passkey) is implemented in a later iteration.

All writes emit event log entries. ``list_credentials`` calls
``track_activity`` at start.

Cross-user ownership is enforced here: ``rename_credential`` /
``delete_credential`` raise ``NotFoundError`` if the target credential belongs
to a different user than the requesting user. Defence-in-depth is added in the
database layer by including ``user_id`` in the WHERE clause.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import database
from fastapi import Request
from schemas.webauthn import (
    BeginRegistrationResponse,
    CompleteRegistrationRequest,
    CompleteRegistrationResponse,
    PasskeyResponse,
)
from services import mfa as mfa_service
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.webauthn import (
    WebAuthnError,
    generate_registration_options_for_user,
    origin_for_request,
    rp_id_for_request,
    rp_name_for_tenant,
    verify_registration,
)

# Registration challenge TTL (seconds). Browsers give the user ~60 seconds for
# the biometric prompt in practice; we allow 5 minutes to cover slower setups.
_REGISTRATION_CHALLENGE_TTL_S = 300

# Session keys for the registration ceremony.
_SESSION_CHALLENGE_KEY = "webauthn_reg_challenge"
_SESSION_CHALLENGE_AT_KEY = "webauthn_reg_challenge_at"


# =============================================================================
# Internal helpers
# =============================================================================


def _row_to_passkey_response(row: dict) -> PasskeyResponse:
    """Convert a database row into the public-facing ``PasskeyResponse`` schema."""
    created_at = row.get("created_at")
    last_used_at = row.get("last_used_at")
    return PasskeyResponse(
        id=str(row["id"]),
        name=row["name"],
        transports=list(row["transports"]) if row.get("transports") else None,
        backup_eligible=bool(row.get("backup_eligible", False)),
        backup_state=bool(row.get("backup_state", False)),
        created_at=created_at.isoformat() if created_at else "",
        last_used_at=last_used_at.isoformat() if last_used_at else None,
    )


def _load_user_for_registration(tenant_id: str, user_id: str) -> tuple[str, str]:
    """Return (email, display_name) for the user. Raises ValidationError if missing."""
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise ValidationError(
            message="User not found",
            code="user_not_found",
        )
    primary = database.user_emails.get_primary_email(tenant_id, user_id)
    email = primary["email"] if primary else f"user-{user_id}@example.invalid"
    first = user.get("first_name") or ""
    last = user.get("last_name") or ""
    display_name = f"{first} {last}".strip() or email
    return email, display_name


# =============================================================================
# Public API
# =============================================================================


def begin_registration(
    requesting_user: RequestingUser,
    request: Request,
) -> BeginRegistrationResponse:
    """Start a passkey registration ceremony.

    Produces the ``PublicKeyCredentialCreationOptions`` for the browser to feed
    into ``navigator.credentials.create()``. The challenge is stashed in the
    session with a 5-minute TTL.
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]
    track_activity(tenant_id, user_id)

    email, display_name = _load_user_for_registration(tenant_id, user_id)

    # Build exclude_credentials list from the user's existing passkeys.
    existing = database.webauthn_credentials.list_credentials(tenant_id, user_id)
    existing_ids: list[bytes] = [bytes(row["credential_id"]) for row in existing]

    rp_id = rp_id_for_request(request)
    rp_name = rp_name_for_tenant(tenant_id)

    # Encode the user handle as raw bytes of the user's UUID. This is opaque to
    # the authenticator; using the UUID ensures uniqueness and stability.
    user_id_bytes = uuid.UUID(str(user_id)).bytes

    options_dict, challenge_bytes = generate_registration_options_for_user(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id_bytes=user_id_bytes,
        user_name=email,
        user_display_name=display_name,
        existing_credential_ids=existing_ids,
    )

    request.session[_SESSION_CHALLENGE_KEY] = challenge_bytes.hex()
    request.session[_SESSION_CHALLENGE_AT_KEY] = int(time.time())

    return BeginRegistrationResponse(public_key=options_dict)


def complete_registration(
    requesting_user: RequestingUser,
    request: Request,
    payload: CompleteRegistrationRequest,
) -> CompleteRegistrationResponse:
    """Verify and persist a new passkey credential.

    On the user's first passkey registration, if they have no existing backup
    codes, we issue a fresh set once and return them in the response. They are
    never re-issued on subsequent registrations.
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]

    challenge_hex = request.session.pop(_SESSION_CHALLENGE_KEY, None)
    challenge_at = request.session.pop(_SESSION_CHALLENGE_AT_KEY, None)

    if not challenge_hex or not challenge_at:
        raise ValidationError(
            message="No passkey registration in progress",
            code="no_registration_in_progress",
        )

    try:
        age = int(time.time()) - int(challenge_at)
    except (TypeError, ValueError):
        age = _REGISTRATION_CHALLENGE_TTL_S + 1

    if age > _REGISTRATION_CHALLENGE_TTL_S:
        raise ValidationError(
            message="Passkey registration session expired. Please start over.",
            code="registration_session_expired",
        )

    try:
        challenge_bytes = bytes.fromhex(challenge_hex)
    except ValueError as exc:
        raise ValidationError(
            message="Passkey registration session is corrupt. Please start over.",
            code="invalid_registration_challenge",
        ) from exc

    rp_id = rp_id_for_request(request)
    origin = origin_for_request(request)

    try:
        verified = verify_registration(
            response=payload.response,
            expected_challenge=challenge_bytes,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except WebAuthnError as exc:
        raise ValidationError(
            message=f"Passkey registration failed: {exc}",
            code="registration_verification_failed",
        ) from exc

    # Extract transport list from the raw browser response. The browser sends
    # it under response.response.transports when available.
    transports: list[str] | None = None
    inner = payload.response.get("response") if isinstance(payload.response, dict) else None
    if isinstance(inner, dict):
        raw_transports = inner.get("transports")
        if isinstance(raw_transports, list):
            transports = [str(t) for t in raw_transports if isinstance(t, str)]
            if not transports:
                transports = None

    # Note: ``count_credentials`` reads the state *before* the insert, so this
    # is correct for the "first passkey" check.
    existing_count = database.webauthn_credentials.count_credentials(tenant_id, user_id)

    row = database.webauthn_credentials.create_credential(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        credential_id=bytes(verified.credential_id),
        public_key=bytes(verified.credential_public_key),
        name=payload.name,
        sign_count=int(verified.sign_count),
        aaguid=str(verified.aaguid) if verified.aaguid else None,
        transports=transports,
        backup_eligible=bool(verified.credential_backed_up)
        if hasattr(verified, "credential_backed_up")
        else False,
        backup_state=bool(verified.credential_backed_up)
        if hasattr(verified, "credential_backed_up")
        else False,
    )

    metadata: dict[str, Any] = {
        "credential_name": payload.name,
        "backup_eligible": bool(row.get("backup_eligible", False)),
        "transports": transports,
    }
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="webauthn_credential",
        artifact_id=str(row["id"]),
        event_type="passkey_registered",
        metadata=metadata,
    )

    # Issue backup codes once on first passkey registration if the user has
    # none yet. Shared with TOTP, so only generate if the user truly has zero.
    backup_codes: list[str] | None = None
    if existing_count == 0:
        existing_codes = database.mfa.list_backup_codes(tenant_id, user_id)
        if not existing_codes:
            backup_codes = mfa_service.generate_initial_backup_codes(tenant_id, user_id)

    return CompleteRegistrationResponse(
        credential=_row_to_passkey_response(row),
        backup_codes=backup_codes,
    )


def list_credentials(requesting_user: RequestingUser) -> list[PasskeyResponse]:
    """List the requesting user's passkeys."""
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]
    track_activity(tenant_id, user_id)

    rows = database.webauthn_credentials.list_credentials(tenant_id, user_id)
    return [_row_to_passkey_response(row) for row in rows]


def rename_credential(
    requesting_user: RequestingUser,
    credential_uuid: str,
    new_name: str,
) -> PasskeyResponse:
    """Rename one of the requesting user's passkeys."""
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]

    # Strict ownership check: raise NotFoundError if the credential is missing
    # OR belongs to a different user. We do not leak cross-user existence.
    existing = database.webauthn_credentials.get_credential(tenant_id, credential_uuid)
    if not existing or str(existing["user_id"]) != str(user_id):
        raise NotFoundError(
            message="Passkey not found",
            code="passkey_not_found",
        )

    old_name = existing["name"]
    rows = database.webauthn_credentials.rename_credential(
        tenant_id, credential_uuid, user_id, new_name
    )
    if rows == 0:
        # Should never happen after the ownership check, but be defensive.
        raise NotFoundError(
            message="Passkey not found",
            code="passkey_not_found",
        )

    fresh = database.webauthn_credentials.get_credential(tenant_id, credential_uuid)
    assert fresh is not None

    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="webauthn_credential",
        artifact_id=str(credential_uuid),
        event_type="passkey_renamed",
        metadata={"old_name": old_name, "new_name": new_name},
    )

    return _row_to_passkey_response(fresh)


def delete_credential(
    requesting_user: RequestingUser,
    credential_uuid: str,
) -> None:
    """Delete one of the requesting user's passkeys."""
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]

    existing = database.webauthn_credentials.get_credential(tenant_id, credential_uuid)
    if not existing or str(existing["user_id"]) != str(user_id):
        raise NotFoundError(
            message="Passkey not found",
            code="passkey_not_found",
        )

    rows = database.webauthn_credentials.delete_credential(tenant_id, credential_uuid, user_id)
    if rows == 0:
        raise NotFoundError(
            message="Passkey not found",
            code="passkey_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="webauthn_credential",
        artifact_id=str(credential_uuid),
        event_type="passkey_deleted",
        metadata={
            "credential_name": existing.get("name"),
            "backup_eligible": bool(existing.get("backup_eligible", False)),
        },
    )
