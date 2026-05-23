"""Outbound SCIM push worker (per-tenant slice processor).

The job handler (`app/jobs/process_scim_push_queue.py`) is a thin wrapper
that discovers which tenants have ready queue entries and calls
`process_pending_pushes(tenant_id)` for each one inside the tenant's RLS
session. All real work lives here.

Per-tenant slice rules (per iteration 4 brief):

- Drain up to 500 ready entries per run per tenant.
- Group entries by SP and process SP buckets sequentially -- per-SP
  fan-out within a tenant is single-threaded to avoid hammering a
  downstream.
- Within an SP bucket, entries process in order of `enqueued_at`.

Per-entry rules:

- Open a `scim_sync_log` row with `status='running'` before the push.
- Re-fetch current resource state at push time (so "last state wins" is
  automatic and the worker can detect "no longer in scope" and emit a
  DELETE instead of a push).
- POST vs PUT: look up the receiver's id mapping in `sp_scim_remote_ids`.
  Mapping present -> PUT `/Users/<remote_id>` (or `/Groups/<remote_id>`)
  to update in place. No mapping -> POST `/Users` (or `/Groups`); on
  success, capture the receiver's `id` from the response and persist
  the mapping.
- DELETE: use the recorded `remote_id` when one exists, fall back to the
  WeftID UUID otherwise (graceful path for pre-mapping rows).
- 404 against a known mapping (PUT/DELETE): invalidate the mapping
  (`scim_remote_id_invalidated` audit event) and treat as retryable so
  the next pass re-POSTs cleanly. 404 without a mapping is already
  classified as `absent` by the generic quirk and treated as success.
- Success: delete the queue row, mark the sync-log row `done`.
- Absent (404 on DELETE, etc.): delete the queue row, mark the sync-log
  row `done` with the `error` column carrying the `already_absent` marker
  so the admin UI can render "skipped: not present".
- Retryable failure: increment `attempts`, schedule the next try on the
  1m / 5m / 30m / 2h backoff, mark the sync-log row `failed`.
- 5th failure: set `dead_letter_at` on the queue row, mark the latest
  sync-log row `dead_letter`.
- Permanent failure (4xx other than 429): treat as "no point retrying"
  and dead-letter immediately, recording the reason.

Sync-log writes are best-effort observability and do not need to be
atomic with queue mutations. The queue is the source of truth for
"what needs doing"; the sync-log is the audit trail.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

import database

from . import client as scim_client
from . import payload as scim_payload
from . import remote_ids as scim_remote_ids
from . import sync_log as scim_sync_log

logger = logging.getLogger(__name__)

# Marker string written into `scim_sync_log.error` for absent-resource
# outcomes (e.g. 404 on DELETE). Status remains `done`; the marker
# tells the admin UI to render "Skipped: resource already absent at
# receiver" instead of implying a real mutation happened. Worker code
# and admin templates both reference this constant so a single change
# updates both surfaces.
ABSENT_MARKER_PREFIX = "already_absent"

# Worker-level retry backoff (transport-level retry lives inside `client`).
# `_BACKOFF_SCHEDULE[N]` is the delay applied AFTER attempt N has failed
# (so index 1 == "wait this long before attempting #2"). Index 0 is
# unused. After the 5th failed attempt the entry is dead-lettered.
# Cumulative wait between attempts 1 and 5 is ~2h36m -- the right order
# for "SP is having a bad day" vs. "our config is wrong". (The iteration
# brief named an "8h" slot for after attempt #5, but attempt #5 dead-
# letters immediately, so the would-be 5th wait is never scheduled.)
_BACKOFF_SCHEDULE = [
    timedelta(0),  # unused (no scheduling before the first attempt)
    timedelta(minutes=1),  # after attempt #1 -> wait for #2
    timedelta(minutes=5),  # after attempt #2 -> wait for #3
    timedelta(minutes=30),  # after attempt #3 -> wait for #4
    timedelta(hours=2),  # after attempt #4 -> wait for #5
]
_MAX_ATTEMPTS = 5

# Per-tenant drain cap per worker run.
_TENANT_DRAIN_LIMIT = 500


def process_pending_pushes(
    tenant_id: str,
    *,
    now: datetime | None = None,
    token_resolver: Any = None,
    http_client: Any = None,
) -> dict[str, Any]:
    """Process up to 500 ready queue entries for one tenant.

    Caller is responsible for opening the tenant-scoped session before
    calling. The cross-tenant iteration lives in the job handler.

    Args:
        tenant_id: Tenant scope (already active on the current session).
        now: Optional override for "current time" (tests).
        token_resolver: Optional callable
            `(tenant_id, sp_id) -> tuple[str, str] | str | None` that
            returns either `(credential_id, plaintext)` or just the
            plaintext (legacy shape, no last-used tracking) or None.
            Defaults to `_default_token_resolver` which returns None.
            The worker treats a missing token as a permanent failure and
            dead-letters the entry immediately.
        http_client: Optional `httpx.Client` shared across requests.

    Returns:
        Dict with counts: `entries_processed`, `succeeded`, `retried`,
        `dead_lettered`, `skipped` (no SCIM target configured),
        `absent` (resource was already gone at the receiver).
    """
    now = now or datetime.now(UTC)
    resolver = token_resolver or _default_token_resolver

    entries = database.scim_push_queue.list_ready_entries(tenant_id, limit=_TENANT_DRAIN_LIMIT)
    if not entries:
        return _empty_summary()

    # Group by SP; process SP buckets sequentially. The list_ready_entries
    # query already orders by enqueued_at, so the per-SP lists inherit
    # FIFO order.
    by_sp: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        by_sp[str(entry["sp_id"])].append(entry)

    summary = _empty_summary()
    summary["entries_processed"] = len(entries)

    for sp_id, sp_entries in by_sp.items():
        sp = database.service_providers.get_scim_target(tenant_id, sp_id)
        if sp is None or not sp.get("scim_enabled") or not sp.get("scim_target_url"):
            # SP was deleted, SCIM was disabled, or target URL is gone.
            # Drop the queue rows -- there is no useful retry. The next
            # config change will re-enqueue if needed.
            for entry in sp_entries:
                _drop_orphaned_entry(tenant_id, entry, sp)
                summary["skipped"] += 1
            continue

        resolved = resolver(tenant_id, sp_id)
        # Three accepted shapes:
        #   ("ok", credential_id, plaintext)        -- new production shape (success)
        #   ("decrypt_failed", credential_id)       -- new production shape (decrypt failure)
        #   (credential_id, plaintext)              -- legacy tuple (treated as success)
        #   plaintext str | None                    -- legacy bare-string fixture shape
        credential_id: str | None
        token: str | None
        decrypt_failed_credential_id: str | None = None
        if isinstance(resolved, tuple):
            if len(resolved) == 3 and resolved[0] == "ok":
                _, credential_id, token = resolved
            elif len(resolved) == 2 and resolved[0] == "decrypt_failed":
                credential_id = None
                token = None
                decrypt_failed_credential_id = resolved[1]
            elif len(resolved) == 2:
                # Legacy `(credential_id, plaintext)` shape.
                credential_id, token = resolved
            else:  # pragma: no cover - defensive
                credential_id = None
                token = None
        else:
            credential_id = None
            token = resolved
        for entry in sp_entries:
            outcome = _process_entry(
                tenant_id=tenant_id,
                sp=sp,
                entry=entry,
                token=token,
                credential_id=credential_id,
                decrypt_failed_credential_id=decrypt_failed_credential_id,
                now=now,
                http_client=http_client,
            )
            summary[outcome] += 1

    return summary


def _empty_summary() -> dict[str, int]:
    return {
        "entries_processed": 0,
        "succeeded": 0,
        "retried": 0,
        "dead_lettered": 0,
        "skipped": 0,
        "absent": 0,
    }


def _default_token_resolver(tenant_id: str, sp_id: str) -> str | None:
    """Default credential resolver (placeholder until iteration 5).

    Iteration 1 stores SCIM credentials as SHA-256 hashes only, which is
    the right shape for *inbound* token verification but cannot recover
    the plaintext that an *outbound* push needs. Iteration 5 will add an
    encrypted plaintext store. Until then this resolver returns None and
    every push gets dead-lettered with a clear reason -- safer than
    sending a bogus header to a real SP.

    Tests inject their own resolver via the `token_resolver` kwarg on
    `process_pending_pushes` so the worker is fully exercisable today.
    """
    return None


def _drop_orphaned_entry(tenant_id: str, entry: dict, sp: dict | None) -> None:
    """Drop a queue entry whose SP is gone / disabled / has no target.

    Writes a sync-log row so the disposition is visible to admins. Best-
    effort: a failure here must not block the drain.
    """
    reason = "scim_target_missing" if sp is None else "scim_disabled_or_no_target"
    try:
        log_id = scim_sync_log.start_attempt(
            tenant_id=tenant_id,
            sp_id=str(entry["sp_id"]),
            resource_type=str(entry["resource_type"]),
            resource_id=str(entry["resource_id"]),
            attempt=int(entry["attempts"]),
            started_at=datetime.now(UTC),
        )
        scim_sync_log.mark_dead_letter(tenant_id, log_id, reason)
    except Exception:  # noqa: BLE001
        logger.exception(
            "Failed to write sync-log row for orphaned queue entry %s",
            entry["id"],
        )
    try:
        database.scim_push_queue.delete_entry(tenant_id, str(entry["id"]))
    except Exception:  # noqa: BLE001
        logger.exception("Failed to delete orphaned queue entry %s", entry["id"])


def _process_entry(
    *,
    tenant_id: str,
    sp: dict,
    entry: dict,
    token: str | None,
    credential_id: str | None,
    decrypt_failed_credential_id: str | None = None,
    now: datetime,
    http_client: Any,
) -> str:
    """Process a single queue entry. Returns the summary bucket name."""
    entry_id = str(entry["id"])
    sp_id = str(sp["id"])
    resource_type = str(entry["resource_type"])
    resource_id = str(entry["resource_id"])
    attempt_number = int(entry["attempts"]) + 1

    log_id = scim_sync_log.start_attempt(
        tenant_id=tenant_id,
        sp_id=sp_id,
        resource_type=resource_type,
        resource_id=resource_id,
        attempt=attempt_number,
        started_at=now,
    )

    if resource_type not in ("user", "group"):
        # Unknown resource type is a permanent condition that retrying
        # cannot fix. Dead-letter immediately rather than burning the
        # 5-attempt budget on a guaranteed-broken row.
        return _record_dead_letter(
            tenant_id,
            entry,
            log_id,
            f"unknown_resource_type: {resource_type!r}",
        )

    if decrypt_failed_credential_id is not None:
        # Credential row exists but its ciphertext could not be
        # decrypted. This is a distinct failure mode from "no
        # credential" -- typically a SECRET_KEY rotation without a
        # re-encrypt. Dead-letter so the admin sees a specific reason
        # in the sync-log panel instead of the generic "configure a
        # token" message.
        return _record_dead_letter(
            tenant_id,
            entry,
            log_id,
            (
                f"credential_decrypt_failed: credential {decrypt_failed_credential_id} "
                "ciphertext could not be decrypted (check SECRET_KEY rotation)"
            ),
        )

    if token is None:
        # No way to authenticate -- dead-letter immediately rather than
        # incrementing attempts on a problem the worker cannot fix.
        return _record_dead_letter(
            tenant_id,
            entry,
            log_id,
            "no_credential_source: outbound SCIM credential is not configured for this SP",
        )

    try:
        result = _dispatch_push(
            sp=sp,
            resource_type=resource_type,
            resource_id=resource_id,
            token=token,
            http_client=http_client,
            tenant_id=tenant_id,
        )
    except Exception as exc:  # noqa: BLE001
        # Programmer-level failure inside payload build or scope check.
        # Treat as retryable so a code fix on a redeploy gets a clean
        # second chance; bounded by the attempts counter.
        logger.exception("SCIM push entry %s raised unexpectedly: %s", entry_id, exc)
        return _record_retry_or_dead_letter(
            tenant_id, entry, log_id, now, f"worker_exception: {type(exc).__name__}: {exc}"
        )

    if result.status == "success":
        return _record_success(tenant_id, entry, log_id, credential_id)
    if result.status == "absent":
        return _record_absent(tenant_id, entry, log_id, credential_id, result)
    if result.status == "permanent":
        return _record_dead_letter(
            tenant_id,
            entry,
            log_id,
            _format_reason("permanent", result),
        )
    # retryable
    return _record_retry_or_dead_letter(
        tenant_id,
        entry,
        log_id,
        now,
        _format_reason("retryable", result),
    )


def _dispatch_push(
    *,
    sp: dict,
    resource_type: str,
    resource_id: str,
    token: str,
    http_client: Any,
    tenant_id: str,
) -> scim_client.PushResult:
    """Resolve current resource state and call the right client method.

    Decides POST vs PUT based on whether we have a recorded `remote_id`
    mapping for this (sp, resource_type, weftid_id) triple. On a
    successful POST, captures the receiver's `id` and persists the
    mapping. On a 404 against a known mapping (PUT/DELETE), invalidates
    the mapping so the next attempt re-POSTs.

    Returns the `PushResult` from the transport layer (possibly after
    mapping bookkeeping); the worker maps that into queue/log mutations.
    """
    sp_id = str(sp["id"])

    if resource_type == "user":
        return _dispatch_user(
            sp=sp,
            sp_id=sp_id,
            tenant_id=tenant_id,
            user_id=resource_id,
            token=token,
            http_client=http_client,
        )

    if resource_type == "group":
        return _dispatch_group(
            sp=sp,
            sp_id=sp_id,
            tenant_id=tenant_id,
            group_id=resource_id,
            token=token,
            http_client=http_client,
        )

    raise ValueError(f"Unknown resource_type {resource_type!r}")


def _dispatch_user(
    *,
    sp: dict,
    sp_id: str,
    tenant_id: str,
    user_id: str,
    token: str,
    http_client: Any,
) -> scim_client.PushResult:
    """Push or delete a single user, honoring the remote-id mapping."""
    mapping = database.scim_remote_ids.get_one(tenant_id, sp_id, "user", user_id)
    remote_id = str(mapping["remote_id"]) if mapping else None

    user = database.user_emails.get_user_with_primary_email(tenant_id, user_id)
    if user is None:
        # User vanished entirely -- emit a DELETE so the downstream SP
        # deprovisions. Use the receiver's id when we have one, else fall
        # back to the WeftID UUID (the externalId) for SPs that key on it.
        delete_target = remote_id or user_id
        result = scim_client.delete_user(sp, delete_target, token=token, http_client=http_client)
        return _handle_404_invalidation(
            tenant_id, sp_id, "user", user_id, mapping is not None, result
        )

    # Compute current scope. If the user is no longer in scope for this
    # SP, push a DELETE / deactivation instead of a create.
    in_scope = _user_in_scope_for_sp(tenant_id, user_id, sp_id)
    if not in_scope:
        delete_target = remote_id or user_id
        result = scim_client.delete_user(sp, delete_target, token=token, http_client=http_client)
        return _handle_404_invalidation(
            tenant_id, sp_id, "user", user_id, mapping is not None, result
        )

    # Combine the auth-shaped user dict with the full user row so the
    # payload builder has every optional field it might want.
    full = database.users.get_user_by_id(tenant_id, user_id) or {}
    merged = {**full, **user}
    resource = scim_payload.build_user_resource(merged)

    if remote_id is not None:
        result = scim_client.put_user(sp, remote_id, resource, token=token, http_client=http_client)
        return _handle_404_invalidation(tenant_id, sp_id, "user", user_id, True, result)

    # No mapping: POST. Capture the receiver's id on success.
    result = scim_client.push_user(sp, resource, token=token, http_client=http_client)
    if result.status == "success" and result.scim_id:
        scim_remote_ids.record_mapping(tenant_id, sp_id, "user", user_id, result.scim_id)
    return result


def _dispatch_group(
    *,
    sp: dict,
    sp_id: str,
    tenant_id: str,
    group_id: str,
    token: str,
    http_client: Any,
) -> scim_client.PushResult:
    """Push or delete a single group, honoring the remote-id mapping."""
    mapping = database.scim_remote_ids.get_one(tenant_id, sp_id, "group", group_id)
    remote_id = str(mapping["remote_id"]) if mapping else None

    group = database.groups.get_group_by_id(tenant_id, group_id)
    if group is None:
        delete_target = remote_id or group_id
        result = scim_client.delete_group(sp, delete_target, token=token, http_client=http_client)
        return _handle_404_invalidation(
            tenant_id, sp_id, "group", group_id, mapping is not None, result
        )

    members = _group_members_for_sp(tenant_id, group_id, sp)

    # Batch-fetch the receiver's id for every member so the Group payload
    # references the receiver's canonical ids, not WeftID UUIDs. Members
    # without a mapping are skipped by the payload builder (with a logged
    # warning) rather than emitting a reference the receiver cannot
    # resolve.
    member_weftid_ids = [str(m["id"]) for m in members]
    remote_id_lookup = database.scim_remote_ids.get_for_users(tenant_id, sp_id, member_weftid_ids)

    resource = scim_payload.build_group_resource(group, members, remote_id_lookup=remote_id_lookup)

    # Per-quirk gate for PUT-on-Groups (GitHub opts out via
    # `GROUP_UPDATE_VERB = "POST"`; see quirks/github.py). When the quirk
    # opts out we always POST regardless of whether a mapping exists --
    # the receiver will 409 on duplicates, matching the pre-mapping
    # behavior. This keeps GitHub tenants on the deterministic
    # "create-only" path rather than newly regressing them with 405s
    # from PUT.
    quirk = scim_client.get_quirk_module(sp.get("scim_kind"))
    group_update_verb = getattr(quirk, "GROUP_UPDATE_VERB", "PUT")

    if remote_id is not None and group_update_verb == "PUT":
        result = scim_client.put_group(
            sp, remote_id, resource, token=token, http_client=http_client
        )
        return _handle_404_invalidation(tenant_id, sp_id, "group", group_id, True, result)

    result = scim_client.push_group(sp, resource, token=token, http_client=http_client)
    if result.status == "success" and result.scim_id:
        scim_remote_ids.record_mapping(tenant_id, sp_id, "group", group_id, result.scim_id)
    return result


def _handle_404_invalidation(
    tenant_id: str,
    sp_id: str,
    resource_type: str,
    weftid_id: str,
    had_mapping: bool,
    result: scim_client.PushResult,
) -> scim_client.PushResult:
    """Invalidate a stale mapping when a PUT/DELETE returns 404.

    Two distinct 404 cases:

    1. PUT 404 with a known mapping (`had_mapping=True`, `permanent`):
       the receiver no longer recognises the id we PUT to. Clear the
       mapping and reclassify as `retryable` so the next pass re-POSTs.

    2. DELETE 404 with a known mapping (`had_mapping=True`, `absent`):
       the resource is genuinely gone at the receiver, but the mapping
       is now stale -- clear it so any future POST of the same WeftID
       resource gets a fresh mapping. The outcome stays `absent` (no
       retry; the queue drain proceeds).

    DELETE 404 without a mapping is already classified `absent` by the
    quirk and needs no mapping bookkeeping. PUT 404 without a mapping
    cannot happen (PUT is only called when a mapping exists).
    """
    if not had_mapping:
        return result
    if result.http_status != 404:
        return result

    scim_remote_ids.invalidate_mapping(
        tenant_id, sp_id, resource_type, weftid_id, reason="remote_404"
    )

    if result.status == "permanent":
        # PUT 404 against a known id: stale mapping. Reclassify as
        # retryable so the next attempt POSTs cleanly. Override the
        # reason so the sync-log breadcrumb is specific.
        return scim_client.PushResult(
            status="retryable",
            http_status=404,
            reason="remote_id_invalidated (HTTP 404; next attempt will POST)",
            scim_id=None,
        )
    # `absent` outcome -- keep as-is; mapping was just cleared
    # opportunistically and we still want the queue row to drain.
    return result


def _user_in_scope_for_sp(tenant_id: str, user_id: str, sp_id: str) -> bool:
    """True iff this user is still in scope for this SCIM-enabled SP."""
    rows = database.scim_scope.scim_sps_granting_user(tenant_id, user_id)
    return any(str(row["id"]) == sp_id for row in rows)


def _group_members_for_sp(tenant_id: str, group_id: str, sp: dict) -> list[dict]:
    """Resolve the SCIM-relevant member list for a group push.

    Honors the SP's `scim_membership_mode`: `effective` returns the
    transitive (closure) membership, `direct` returns only direct
    members. We page through the database getter in batches; SCIM
    Group resources can be large but the database layer paginates
    internally.
    """
    mode = sp.get("scim_membership_mode") or "effective"
    if mode == "direct":
        # Direct memberships only: use list_members.
        # Falls back to effective if a direct-members getter is not
        # available; ours uses get_effective_members with depth=0 filter.
        return _list_direct_members(tenant_id, group_id)
    return _list_effective_members(tenant_id, group_id)


def _list_effective_members(tenant_id: str, group_id: str) -> list[dict]:
    """Paginated walk of all effective members of a group."""
    members: list[dict] = []
    page = 1
    page_size = 200
    while True:
        batch = database.groups.get_effective_members(
            tenant_id, group_id, page=page, page_size=page_size
        )
        if not batch:
            break
        for row in batch:
            members.append(
                {
                    "id": row["user_id"],
                    "email": row.get("email"),
                    "first_name": row.get("first_name"),
                    "last_name": row.get("last_name"),
                }
            )
        if len(batch) < page_size:
            break
        page += 1
    return members


def _list_direct_members(tenant_id: str, group_id: str) -> list[dict]:
    """Direct-only membership: filter effective list by is_direct flag."""
    members: list[dict] = []
    page = 1
    page_size = 200
    while True:
        batch = database.groups.get_effective_members(
            tenant_id, group_id, page=page, page_size=page_size
        )
        if not batch:
            break
        for row in batch:
            if not row.get("is_direct"):
                continue
            members.append(
                {
                    "id": row["user_id"],
                    "email": row.get("email"),
                    "first_name": row.get("first_name"),
                    "last_name": row.get("last_name"),
                }
            )
        if len(batch) < page_size:
            break
        page += 1
    return members


def _record_success(
    tenant_id: str,
    entry: dict,
    log_id: str,
    credential_id: str | None,
) -> str:
    """Drop the queue row, mark the log row done, bump credential last_used.

    Last-used tracking is best-effort: a failure here must not roll back
    the push outcome (the downstream SP already accepted the resource).
    """
    database.scim_push_queue.delete_entry(tenant_id, str(entry["id"]))
    scim_sync_log.mark_done(tenant_id, log_id)
    if credential_id is not None:
        try:
            database.scim_credentials.update_last_used(tenant_id, credential_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "SCIM worker: failed to update_last_used (tenant=%s credential=%s)",
                tenant_id,
                credential_id,
            )
    return "succeeded"


def _record_absent(
    tenant_id: str,
    entry: dict,
    log_id: str,
    credential_id: str | None,
    result: scim_client.PushResult,
) -> str:
    """Resource was already gone at the receiver. Drain the queue row.

    The status stays `done` (no failure, no retry) but the `error` column
    carries the `already_absent` marker. The admin UI checks for this
    prefix and renders "Skipped: resource already absent at receiver".

    Distinct from `_record_success` only in the sync_log marker -- both
    drop the queue row and bump credential last_used. The receiver
    *did* respond, so the credential is still good.
    """
    database.scim_push_queue.delete_entry(tenant_id, str(entry["id"]))
    reason = result.reason or "already_absent (HTTP 404)"
    if not reason.startswith(ABSENT_MARKER_PREFIX):
        reason = f"{ABSENT_MARKER_PREFIX}: {reason}"
    # Reuse `mark_failed` shape to write status+error in one call, then
    # bump back to `done` so the row is visibly successful in admin UI
    # filters. (`mark_done` clears the error column, so we cannot use it
    # directly here.)
    database.scim_sync_log.update_status(
        tenant_id=tenant_id,
        entry_id=log_id,
        status="done",
        error=reason,
        completed=True,
    )
    if credential_id is not None:
        try:
            database.scim_credentials.update_last_used(tenant_id, credential_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "SCIM worker: failed to update_last_used after absent (tenant=%s credential=%s)",
                tenant_id,
                credential_id,
            )
    return "absent"


def _record_retry_or_dead_letter(
    tenant_id: str,
    entry: dict,
    log_id: str,
    now: datetime,
    reason: str,
) -> str:
    """Bump attempts, schedule next try, or dead-letter on the cap."""
    next_attempt_number = int(entry["attempts"]) + 1
    if next_attempt_number >= _MAX_ATTEMPTS:
        return _record_dead_letter(tenant_id, entry, log_id, reason)
    # _BACKOFF_SCHEDULE[N] is the delay before attempt N+1; we are
    # scheduling the delay AFTER incrementing attempts, so index by the
    # just-completed attempt number (== next_attempt_number - 1).
    delay = _BACKOFF_SCHEDULE[next_attempt_number]
    next_at = now + delay
    database.scim_push_queue.mark_attempt_failed(
        tenant_id=tenant_id,
        entry_id=str(entry["id"]),
        error=_truncate_queue_error(reason),
        next_attempt_at=next_at,
    )
    scim_sync_log.mark_failed(tenant_id, log_id, reason)
    return "retried"


def _record_dead_letter(tenant_id: str, entry: dict, log_id: str, reason: str) -> str:
    """Set dead_letter_at on the queue row and mark the log row dead-letter."""
    database.scim_push_queue.mark_dead_letter(
        tenant_id=tenant_id,
        entry_id=str(entry["id"]),
        error=_truncate_queue_error(reason),
    )
    scim_sync_log.mark_dead_letter(tenant_id, log_id, reason)
    return "dead_lettered"


def _format_reason(status: str, result: scim_client.PushResult) -> str:
    """Compact, human-readable reason recorded into the sync-log row.

    Intentionally bounded -- never include the full SCIM payload. The
    audit log carries the status + SCIM error code/detail; full payloads
    are DEBUG-level Python logs only.
    """
    parts = [status]
    if result.http_status is not None:
        parts.append(f"http={result.http_status}")
    if result.reason:
        parts.append(result.reason)
    return " ".join(parts)


# The CHECK constraint on scim_push_queue.last_error is `length <= 4000`.
_MAX_QUEUE_ERROR_LENGTH = 3900


def _truncate_queue_error(error: str) -> str:
    """Truncate the error string for the queue's last_error column."""
    if len(error) <= _MAX_QUEUE_ERROR_LENGTH:
        return error
    return error[: _MAX_QUEUE_ERROR_LENGTH - 3] + "..."
