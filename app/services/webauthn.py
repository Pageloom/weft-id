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
    BeginAuthenticationResponse,
    BeginRegistrationResponse,
    CompleteAuthenticationRequest,
    CompleteRegistrationRequest,
    CompleteRegistrationResponse,
    PasskeyResponse,
)
from services import mfa as mfa_service
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.webauthn import (
    WebAuthnError,
    generate_authentication_options_for_user,
    generate_registration_options_for_user,
    origin_for_request,
    rp_id_for_request,
    rp_name_for_tenant,
    verify_authentication,
    verify_registration,
)

# Registration challenge TTL (seconds). Browsers give the user ~60 seconds for
# the biometric prompt in practice; we allow 5 minutes to cover slower setups.
_REGISTRATION_CHALLENGE_TTL_S = 300

# Session keys for the registration ceremony.
_SESSION_CHALLENGE_KEY = "webauthn_reg_challenge"
_SESSION_CHALLENGE_AT_KEY = "webauthn_reg_challenge_at"

# Session keys for the login (authentication) ceremony. TTL mirrors registration.
_LOGIN_CHALLENGE_KEY = "webauthn_login_challenge"
_LOGIN_CHALLENGE_AT_KEY = "webauthn_login_challenge_at"
_LOGIN_PENDING_USER_KEY = "pending_passkey_user_id"
_LOGIN_CHALLENGE_TTL_S = 300


# =============================================================================
# Internal helpers
# =============================================================================


def _row_to_passkey_response(row: dict) -> PasskeyResponse:
    """Convert a database row into the public-facing ``PasskeyResponse`` schema."""
    return PasskeyResponse(
        id=str(row["id"]),
        name=row["name"],
        transports=list(row["transports"]) if row.get("transports") else None,
        backup_eligible=bool(row.get("backup_eligible", False)),
        backup_state=bool(row.get("backup_state", False)),
        created_at=row["created_at"],
        last_used_at=row.get("last_used_at"),
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


# =============================================================================
# Admin operations (cross-user)
# =============================================================================


def admin_list_credentials(requesting_user: RequestingUser, user_id: str) -> list[PasskeyResponse]:
    """List another user's passkeys. Admin role required."""
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    track_activity(tenant_id, requesting_user["id"])

    rows = database.webauthn_credentials.list_credentials(tenant_id, user_id)
    return [_row_to_passkey_response(row) for row in rows]


def admin_revoke_credential(
    requesting_user: RequestingUser,
    user_id: str,
    credential_uuid: str,
) -> None:
    """Revoke another user's passkey. Admin role required.

    Admin revoke is the compromised-credential path. In addition to deleting
    the credential, all of the target user's OAuth2 tokens are revoked so an
    attacker holding an active access/refresh token is ejected along with the
    passkey they may have stolen.

    Emits ``passkey_deleted`` with ``metadata.revoked_by_admin = True``,
    ``metadata.target_user_id`` and ``metadata.target_user_name`` so audit
    queries can distinguish admin revocations from self-deletions even after
    the target account is anonymized.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    if str(requesting_user["id"]) == str(user_id):
        raise ValidationError(
            message="You cannot revoke your own passkey from the admin view. "
            "Use the account passkeys page instead.",
            code="cannot_revoke_own_passkey",
        )

    target_user = database.users.get_user_by_id(tenant_id, user_id)
    if not target_user:
        raise NotFoundError(message="User not found", code="user_not_found")

    existing = database.webauthn_credentials.get_credential(tenant_id, credential_uuid)
    if not existing or str(existing["user_id"]) != str(user_id):
        raise NotFoundError(
            message="Passkey not found",
            code="passkey_not_found",
        )

    rows = database.webauthn_credentials.delete_credential(
        tenant_id, credential_uuid, str(existing["user_id"])
    )
    if rows == 0:
        raise NotFoundError(
            message="Passkey not found",
            code="passkey_not_found",
        )

    # Revoke OAuth2 tokens so any active attacker session tied to the
    # compromised credential loses access alongside the passkey itself.
    revoked_count = database.oauth2.revoke_all_user_tokens(tenant_id, str(user_id))
    if revoked_count > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=str(user_id),
            event_type="oauth2_user_tokens_revoked",
            artifact_type="user",
            artifact_id=str(user_id),
            metadata={"reason": "admin_revoked_passkey", "tokens_revoked": revoked_count},
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(requesting_user["id"]),
        artifact_type="webauthn_credential",
        artifact_id=str(credential_uuid),
        event_type="passkey_deleted",
        metadata={
            "revoked_by_admin": True,
            "target_user_id": str(user_id),
            "target_user_name": f"{target_user['first_name']} {target_user['last_name']}",
            "credential_name": existing.get("name"),
            "backup_eligible": bool(existing.get("backup_eligible", False)),
        },
    )


# =============================================================================
# Passkey login (authentication ceremony)
# =============================================================================


def user_has_passkey_for_email(tenant_id: str, email: str) -> bool:
    """Return True iff an email maps to a passkey-eligible user.

    Convenience wrapper on ``_resolve_eligible_user`` for callers (the login
    page renderer) that only need to know whether to show the passkey-first
    variant. Anti-enumeration: False on any failing check.
    """
    return _resolve_eligible_user(tenant_id, email.strip().lower()) is not None


def _clear_login_session(session: dict) -> None:
    """Remove all passkey-login session keys in one place."""
    session.pop(_LOGIN_CHALLENGE_KEY, None)
    session.pop(_LOGIN_CHALLENGE_AT_KEY, None)
    session.pop(_LOGIN_PENDING_USER_KEY, None)


def _emit_passkey_failure(
    tenant_id: str,
    user_id: str | None,
    reason: str,
    credential_uuid: str | None = None,
) -> None:
    """Emit ``passkey_auth_failure`` with a stable reason code.

    If ``user_id`` is None (user lookup failed before any ceremony state was
    bound), the tenant id is used as the artifact to keep the event record
    consistent with the anti-enumeration pattern in ``login_failed``.
    """
    actor = user_id or tenant_id
    artifact_type = "webauthn_credential" if credential_uuid else "user"
    artifact_id = credential_uuid or actor
    metadata: dict[str, Any] = {"reason": reason}
    if user_id is None:
        metadata["anonymous"] = True
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(actor),
        artifact_type=artifact_type,
        artifact_id=str(artifact_id),
        event_type="passkey_auth_failure",
        metadata=metadata,
    )


def _resolve_eligible_user(tenant_id: str, email: str) -> dict | None:
    """Return the user dict iff they are eligible for passkey login.

    Eligible means: the user exists with a verified email, is NOT linked to a
    SAML IdP, is NOT inactivated, and has at least one registered passkey.
    Anti-enumeration: returns None for every failing case (the caller never
    distinguishes the reason).
    """
    user = database.users.get_user_auth_info(tenant_id, email)
    if not user:
        return None
    if user.get("saml_idp_id"):
        return None
    if user.get("is_inactivated"):
        return None
    count = database.webauthn_credentials.count_credentials(tenant_id, str(user["id"]))
    if count <= 0:
        return None
    return user


def begin_authentication(
    request: Request,
    tenant_id: str,
    email: str,
) -> BeginAuthenticationResponse | None:
    """Start a passkey authentication ceremony for an identified user.

    Returns None if the user is not eligible for passkey login. Callers treat
    None as "fall through to password". Anti-enumeration: identical None
    return for nonexistent user, IdP user, inactivated user, and zero-passkey
    user.
    """
    normalized = email.strip().lower()
    user = _resolve_eligible_user(tenant_id, normalized)
    if user is None:
        return None

    user_id = str(user["id"])
    credentials = database.webauthn_credentials.list_credentials(tenant_id, user_id)
    credential_ids = [bytes(row["credential_id"]) for row in credentials]
    if not credential_ids:
        return None

    rp_id = rp_id_for_request(request)
    options_dict, challenge_bytes = generate_authentication_options_for_user(
        rp_id=rp_id,
        allowed_credential_ids=credential_ids,
    )

    request.session[_LOGIN_CHALLENGE_KEY] = challenge_bytes.hex()
    request.session[_LOGIN_CHALLENGE_AT_KEY] = int(time.time())
    request.session[_LOGIN_PENDING_USER_KEY] = user_id

    return BeginAuthenticationResponse(public_key=options_dict)


def complete_authentication(
    request: Request,
    tenant_id: str,
    payload: CompleteAuthenticationRequest,
) -> str:
    """Verify an assertion, update auth state, and finalize login.

    Returns the redirect URL to follow on success. Raises ``ValidationError``
    with a stable ``code`` on any failure so callers can translate to an
    appropriate response.
    """
    from webauthn.helpers import base64url_to_bytes

    session = request.session
    pending_user_id = session.get(_LOGIN_PENDING_USER_KEY)
    challenge_hex = session.get(_LOGIN_CHALLENGE_KEY)
    challenge_at = session.get(_LOGIN_CHALLENGE_AT_KEY)

    if not pending_user_id or not challenge_hex or not challenge_at:
        _clear_login_session(session)
        _emit_passkey_failure(tenant_id, None, "no_challenge")
        raise ValidationError(
            message="No passkey sign-in in progress",
            code="no_challenge",
        )

    # TTL check
    try:
        age = int(time.time()) - int(challenge_at)
    except (TypeError, ValueError):
        age = _LOGIN_CHALLENGE_TTL_S + 1
    if age > _LOGIN_CHALLENGE_TTL_S:
        _clear_login_session(session)
        _emit_passkey_failure(tenant_id, str(pending_user_id), "expired_challenge")
        raise ValidationError(
            message="Passkey sign-in expired. Please start over.",
            code="expired_challenge",
        )

    try:
        challenge_bytes = bytes.fromhex(str(challenge_hex))
    except ValueError as exc:
        _clear_login_session(session)
        _emit_passkey_failure(tenant_id, str(pending_user_id), "corrupt_challenge")
        raise ValidationError(
            message="Passkey session corrupt",
            code="corrupt_challenge",
        ) from exc

    # Resolve the specific credential the browser used. We match the returned
    # rawId (base64url) bytes against the user's registered credential_id
    # bytes. This is defence-in-depth on top of the allowCredentials we sent
    # at begin time.
    raw = payload.response if isinstance(payload.response, dict) else {}
    raw_id_b64 = raw.get("rawId") or raw.get("id")
    if not raw_id_b64 or not isinstance(raw_id_b64, str):
        _clear_login_session(session)
        _emit_passkey_failure(tenant_id, str(pending_user_id), "unknown_credential")
        raise ValidationError(
            message="Unknown credential",
            code="unknown_credential",
        )

    try:
        returned_id_bytes = base64url_to_bytes(raw_id_b64)
    except Exception as exc:
        _clear_login_session(session)
        _emit_passkey_failure(tenant_id, str(pending_user_id), "unknown_credential")
        raise ValidationError(
            message="Unknown credential",
            code="unknown_credential",
        ) from exc

    rows = database.webauthn_credentials.list_credentials(tenant_id, str(pending_user_id))
    stored = next((r for r in rows if bytes(r["credential_id"]) == returned_id_bytes), None)
    if stored is None:
        _clear_login_session(session)
        _emit_passkey_failure(tenant_id, str(pending_user_id), "unknown_credential")
        raise ValidationError(
            message="Unknown credential",
            code="unknown_credential",
        )

    credential_uuid = str(stored["id"])
    stored_sign_count = int(stored["sign_count"])
    backup_eligible = bool(stored.get("backup_eligible", False))

    # For synced platform authenticators (backup_eligible=True), the sign
    # counter may legitimately reset or stay at 0 on every assertion. We pass
    # 0 to the verifier so the library's strict-monotonic check does not
    # reject synced credentials. Clone detection for BE=false credentials
    # still trips the library's check (sign-count regression = clone).
    effective_current = 0 if backup_eligible else stored_sign_count

    rp_id = rp_id_for_request(request)
    origin = origin_for_request(request)

    try:
        verified = verify_authentication(
            response=raw,
            expected_challenge=challenge_bytes,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes(stored["public_key"]),
            credential_current_sign_count=effective_current,
        )
    except WebAuthnError as exc:
        msg = str(exc).lower()
        # Sign-count regression for a non-synced credential suggests a clone.
        # (We bypass the check for BE=true above, so hitting it means BE=false.)
        if "sign count" in msg or "counter" in msg:
            _clear_login_session(session)
            database.webauthn_credentials.delete_credential(
                tenant_id, credential_uuid, str(pending_user_id)
            )
            log_event(
                tenant_id=tenant_id,
                actor_user_id=str(pending_user_id),
                artifact_type="webauthn_credential",
                artifact_id=credential_uuid,
                event_type="passkey_deleted",
                metadata={
                    "reason": "clone_suspected",
                    "credential_name": stored.get("name"),
                },
            )
            _emit_passkey_failure(
                tenant_id,
                str(pending_user_id),
                "clone_suspected",
                credential_uuid=credential_uuid,
            )
            raise ValidationError(
                message="Passkey sign-in failed",
                code="clone_suspected",
            ) from exc

        _clear_login_session(session)
        _emit_passkey_failure(
            tenant_id,
            str(pending_user_id),
            "bad_signature",
            credential_uuid=credential_uuid,
        )
        raise ValidationError(
            message="Passkey sign-in failed",
            code="bad_signature",
        ) from exc

    # Success: persist the new sign count and refreshed backup_state.
    new_sign_count = int(getattr(verified, "new_sign_count", 0))
    new_backup_state = bool(
        getattr(verified, "credential_backed_up", stored.get("backup_state", False))
    )
    database.webauthn_credentials.update_auth_state(
        tenant_id=tenant_id,
        credential_uuid=credential_uuid,
        user_id=str(pending_user_id),
        sign_count=new_sign_count,
        backup_state=new_backup_state,
    )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(pending_user_id),
        artifact_type="webauthn_credential",
        artifact_id=credential_uuid,
        event_type="passkey_auth_success",
        metadata={
            "credential_id": credential_uuid,
            "credential_name": stored.get("name"),
        },
    )

    # Clear ceremony state before the shared completion helper regenerates
    # the session.
    _clear_login_session(session)

    # Finalize login via the shared helper (emits ``user_signed_in``,
    # regenerates session, binds SSO context, updates last_login/tz/locale,
    # returns a redirect to dashboard or SSO consent).
    from routers.auth._login_completion import complete_authenticated_login

    redirect = complete_authenticated_login(
        request=request,
        tenant_id=tenant_id,
        user_id=str(pending_user_id),
        mfa_method="passkey",
    )
    return redirect.headers["location"]
