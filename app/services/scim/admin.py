"""Outbound SCIM admin services.

Business logic for the admin UI and API surfaces added in iteration 5:

- Read/update SCIM config on a service provider (`scim_enabled`,
  `scim_target_url`, `scim_kind`, `scim_membership_mode`,
  `scim_log_retention`).
- Bearer credential management: create / rotate / revoke. Plaintext is
  returned once at creation/rotation and persisted only as ciphertext
  (`encrypted_plaintext`) + SHA-256 hash. The worker resolves the
  plaintext at push time via the Fernet-derived key.
- Sync log read (paginated, filterable) and queue-status snapshot.
- Retry-dead-lettered control: clears `dead_letter_at` on queue rows so
  the worker re-attempts them on its next pass.

Authorization: all functions require admin role. Every write emits an
audit event via `log_event()`. Reads call `track_activity()`.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any, cast

import database
from schemas.scim_admin import (
    ScimConfig,
    ScimConfigUpdate,
    ScimCredential,
    ScimCredentialCreated,
    ScimCredentialList,
    ScimKind,
    ScimLogRetention,
    ScimMembershipMode,
    ScimQueueStatus,
    ScimResourceType,
    ScimRetryResult,
    ScimSyncLogEntry,
    ScimSyncLogList,
    ScimSyncStatus,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.scim_crypto import encrypt_token

# Default rotation overlap. Both the old and the new token remain valid
# for this long after a rotate so an in-flight worker can finish a push
# without a credential swap mid-flight.
DEFAULT_ROTATION_OVERLAP_HOURS = 24

# Token shape: 192 bits of entropy, urlsafe base64 -- long enough that
# operators won't try to reuse them across SPs, short enough to copy/paste.
_TOKEN_BYTES = 24


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_config(sp_row: dict) -> ScimConfig:
    return ScimConfig(
        sp_id=str(sp_row["id"]),
        scim_enabled=bool(sp_row.get("scim_enabled", False)),
        scim_target_url=sp_row.get("scim_target_url"),
        scim_kind=cast(ScimKind, sp_row.get("scim_kind") or "generic"),
        scim_membership_mode=cast(
            ScimMembershipMode, sp_row.get("scim_membership_mode") or "effective"
        ),
        scim_log_retention=cast(ScimLogRetention, str(sp_row.get("scim_log_retention") or "3")),
    )


def _row_to_credential(row: dict) -> ScimCredential:
    return ScimCredential(
        id=str(row["id"]),
        sp_id=str(row["sp_id"]),
        created_by_user_id=str(row["created_by_user_id"]),
        created_at=row["created_at"],
        revoked_at=row.get("revoked_at"),
        last_used_at=row.get("last_used_at"),
    )


def _row_to_sync_log(row: dict) -> ScimSyncLogEntry:
    return ScimSyncLogEntry(
        id=str(row["id"]),
        sp_id=str(row["sp_id"]),
        resource_type=cast(ScimResourceType, row["resource_type"]),
        resource_id=str(row["resource_id"]),
        status=cast(ScimSyncStatus, row["status"]),
        attempt=int(row.get("attempt") or 0),
        error=row.get("error"),
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        created_at=row["created_at"],
    )


def _require_sp(tenant_id: str, sp_id: str) -> dict:
    sp = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")
    return sp


def _generate_token() -> tuple[str, bytes]:
    """Mint a new bearer token. Returns (plaintext, ciphertext)."""
    plaintext = secrets.token_urlsafe(_TOKEN_BYTES)
    cipher = encrypt_token(plaintext)
    return plaintext, cipher


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def get_scim_config(requesting_user: RequestingUser, sp_id: str) -> ScimConfig:
    """Return the SCIM configuration for one SP.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    sp = _require_sp(requesting_user["tenant_id"], sp_id)
    return _row_to_config(sp)


def update_scim_config(
    requesting_user: RequestingUser,
    sp_id: str,
    data: ScimConfigUpdate,
) -> ScimConfig:
    """Update SCIM-relevant columns on a service provider.

    Authorization: Requires admin role.
    Logs: `scim_config_updated` (always when any field changes).
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    existing = _require_sp(tenant_id, sp_id)

    updates: dict[str, Any] = {}
    fields = data.model_fields_set
    if "scim_enabled" in fields:
        updates["scim_enabled"] = bool(data.scim_enabled)
    if "scim_target_url" in fields:
        # Empty string means "clear" -> NULL.
        updates["scim_target_url"] = data.scim_target_url or None
    if "scim_kind" in fields and data.scim_kind:
        updates["scim_kind"] = data.scim_kind
    if "scim_membership_mode" in fields and data.scim_membership_mode:
        updates["scim_membership_mode"] = data.scim_membership_mode
    if "scim_log_retention" in fields and data.scim_log_retention:
        updates["scim_log_retention"] = data.scim_log_retention

    if not updates:
        raise ValidationError(
            message="At least one field must be provided for update",
            code="scim_config_no_fields",
        )

    if updates.get("scim_enabled") and not (
        updates.get("scim_target_url") or existing.get("scim_target_url")
    ):
        raise ValidationError(
            message="A SCIM target URL is required before SCIM can be enabled.",
            code="scim_target_url_required",
        )

    changed: dict[str, dict[str, Any]] = {}
    for key, new_value in updates.items():
        old_value = existing.get(key)
        if old_value != new_value:
            changed[key] = {"old": old_value, "new": new_value}

    row = database.service_providers.update_service_provider(tenant_id, sp_id, **updates)
    if row is None:
        # Race: SP deleted between the lookup and the update.
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    if changed:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="service_provider",
            artifact_id=sp_id,
            event_type="scim_config_updated",
            metadata={"changed_fields": sorted(changed.keys()), "changes": changed},
        )

    return _row_to_config(row)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def list_credentials(requesting_user: RequestingUser, sp_id: str) -> ScimCredentialList:
    """List still-usable bearer credentials for one SP.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    _require_sp(tenant_id, sp_id)

    rows = database.scim_credentials.list_usable_credentials(tenant_id, sp_id)
    items = [_row_to_credential(row) for row in rows]
    return ScimCredentialList(items=items, total=len(items))


def create_credential(
    requesting_user: RequestingUser,
    sp_id: str,
) -> ScimCredentialCreated:
    """Mint a new bearer credential for an SP.

    Returns the plaintext token in the response. The plaintext is never
    persisted in cleartext after this call: the database only stores the
    Fernet-encrypted plaintext (for the outbound push worker to decrypt
    and present to the downstream SP).

    Authorization: Requires admin role.
    Logs: `scim_token_created`.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    _require_sp(tenant_id, sp_id)

    plaintext, cipher = _generate_token()
    row = database.scim_credentials.create_credential(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        created_by_user_id=requesting_user["id"],
        encrypted_plaintext=cipher,
    )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="scim_token_created",
        metadata={"credential_id": str(row["id"])},
    )

    return ScimCredentialCreated(
        id=str(row["id"]),
        sp_id=sp_id,
        created_at=row["created_at"],
        plaintext=plaintext,
        rotated_from_id=None,
        rotated_from_revoke_at=None,
    )


def rotate_credential(
    requesting_user: RequestingUser,
    sp_id: str,
    credential_id: str,
    overlap_hours: int = DEFAULT_ROTATION_OVERLAP_HOURS,
) -> ScimCredentialCreated:
    """Rotate a bearer credential.

    Creates a fresh credential AND schedules the supplied existing
    credential for revocation `overlap_hours` from now. Both tokens are
    accepted by the worker during the overlap window.

    Authorization: Requires admin role.
    Logs: `scim_token_rotated` on the old credential.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    _require_sp(tenant_id, sp_id)

    if overlap_hours < 0 or overlap_hours > 720:
        # 720h = 30d, the upper bound the UI selector should cap at.
        raise ValidationError(
            message="overlap_hours must be between 0 and 720",
            code="scim_overlap_out_of_range",
        )

    existing = database.scim_credentials.list_active_credentials(tenant_id, sp_id)
    existing_ids = {str(row["id"]) for row in existing}
    if credential_id not in existing_ids:
        raise NotFoundError(
            message="Credential not found or already revoked",
            code="scim_credential_not_found",
        )

    plaintext, cipher = _generate_token()
    new_row = database.scim_credentials.create_credential(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        created_by_user_id=requesting_user["id"],
        encrypted_plaintext=cipher,
    )

    if overlap_hours == 0:
        database.scim_credentials.mark_revoked(tenant_id, credential_id)
        revoke_at = datetime.now(tz=new_row["created_at"].tzinfo)
    else:
        database.scim_credentials.schedule_revocation(
            tenant_id,
            credential_id,
            overlap_interval=f"{overlap_hours} hours",
        )
        revoke_at = datetime.now(tz=new_row["created_at"].tzinfo) + timedelta(hours=overlap_hours)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="scim_token_rotated",
        metadata={
            "old_credential_id": credential_id,
            "new_credential_id": str(new_row["id"]),
            "overlap_hours": overlap_hours,
        },
    )

    return ScimCredentialCreated(
        id=str(new_row["id"]),
        sp_id=sp_id,
        created_at=new_row["created_at"],
        plaintext=plaintext,
        rotated_from_id=credential_id,
        rotated_from_revoke_at=revoke_at,
    )


def revoke_credential(
    requesting_user: RequestingUser,
    sp_id: str,
    credential_id: str,
) -> None:
    """Immediately revoke a bearer credential.

    No overlap window. The worker stops accepting this credential as soon
    as the row is updated. Use `rotate_credential` for the safer flow.

    Authorization: Requires admin role.
    Logs: `scim_token_revoked`.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    _require_sp(tenant_id, sp_id)

    rows = database.scim_credentials.mark_revoked(tenant_id, credential_id)
    if rows == 0:
        raise NotFoundError(
            message="Credential not found or already revoked",
            code="scim_credential_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="scim_token_revoked",
        metadata={"credential_id": credential_id},
    )


# ---------------------------------------------------------------------------
# Sync activity
# ---------------------------------------------------------------------------


def list_sync_log(
    requesting_user: RequestingUser,
    sp_id: str,
    page: int = 1,
    page_size: int = 50,
    status: str | None = None,
) -> ScimSyncLogList:
    """List recent sync-log entries for one SP, newest first.

    `completed_at DESC NULLS FIRST` ordering surfaces in-flight rows.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    _require_sp(tenant_id, sp_id)

    page = max(1, page)
    page_size = max(1, min(200, page_size))
    offset = (page - 1) * page_size

    rows = database.scim_sync_log.list_recent_for_sp(
        tenant_id, sp_id, limit=page_size, offset=offset, status=status
    )
    total = database.scim_sync_log.count_for_sp(tenant_id, sp_id, status=status)

    return ScimSyncLogList(
        items=[_row_to_sync_log(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


def get_queue_status(requesting_user: RequestingUser, sp_id: str) -> ScimQueueStatus:
    """Return pending and dead-letter counts for one SP.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    _require_sp(tenant_id, sp_id)

    counts = database.scim_push_queue.count_pending_for_sp(tenant_id, sp_id)
    return ScimQueueStatus(
        sp_id=sp_id,
        pending=int(counts.get("pending") or 0),
        dead_lettered=int(counts.get("dead_lettered") or 0),
    )


def retry_dead_lettered(
    requesting_user: RequestingUser,
    sp_id: str,
) -> ScimRetryResult:
    """Clear `dead_letter_at` on every dead-lettered queue row for this SP.

    The worker picks the revived rows up on its next pass. Each cleared
    row gets a fresh `attempt` counter and `next_attempt_at` of NULL.

    Authorization: Requires admin role.
    Logs: a `scim_config_updated` event with metadata describing the
    retry-dead-lettered action. (No dedicated event type to keep the
    registry small; the metadata distinguishes it.)
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    _require_sp(tenant_id, sp_id)

    revived = database.scim_push_queue.revive_dead_lettered_for_sp(tenant_id, sp_id)

    if revived:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="service_provider",
            artifact_id=sp_id,
            event_type="scim_config_updated",
            metadata={"action": "retry_dead_lettered", "revived": revived},
            dispatch_scim=False,
        )

    return ScimRetryResult(sp_id=sp_id, revived=revived)
