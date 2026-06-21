"""User attribute service layer.

Two-space storage model:

* ``user_attributes`` -- canonical user attribute set. Owned by the user
  or admin. Read by SP assertion builders. Writers: ``set_user_attribute``,
  ``clear_user_attribute``, and ``apply_idp_attributes`` (when the tenant
  has ``mirror_from_idp=true`` for the key).

* ``user_idp_attributes`` -- read-only audit/info copy of what each
  connected IdP last sent. Writer: ``apply_idp_attributes`` only.

Lock and policy enforcement happen here, not in the database. Admins
always bypass the per-attribute lock. The IdP-mirror writer is also not
subject to the lock -- "users can't edit" is not "the system can't
update".

Force profile completion (Iteration 7)
-------------------------------------

Two distinct surfaces compute "incomplete profile" status:

* ``compute_missing_required(tenant_id, user_id)`` returns every required+
  enabled attribute the user is missing, paired with the ``locked`` flag
  from tenant config. Callers decide how to use it:
    - Dashboard banner / force-completion flow: filter to ``locked=False``.
      Those are the fields the user can fix themselves.
    - Admin Todo view: shows both locked and unlocked.

* ``list_users_with_missing_required(requesting_user)`` aggregates the
  same data across every user in the tenant, in one query, so the admin
  Todo view renders without an N+1 fan-out.

``force_profile_completion`` on ``users`` is set by
``bulk_set_force_profile_completion`` (admin bulk action) and cleared
inside ``set_user_attribute`` once the user no longer has any unlocked
missing required attributes.
"""

from __future__ import annotations

import database
from constants.user_attributes import (
    ATTRIBUTES_BY_KEY,
    is_standard_attribute,
    serialize,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from services.settings.security import can_user_edit_profile
from services.types import RequestingUser

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_known_attribute(attribute_key: str) -> None:
    if not is_standard_attribute(attribute_key):
        raise ValidationError(
            message=f"Unknown attribute key: {attribute_key}",
            code="unknown_attribute_key",
            field="attribute_key",
        )


def _require_enabled(tenant_id: str, attribute_key: str) -> dict:
    """Return the config row, raising if the attribute is disabled or missing."""
    config = database.tenant_attribute_config.get_config(tenant_id, attribute_key)
    if config is None or not config.get("enabled"):
        raise ValidationError(
            message=f"Attribute {attribute_key} is not enabled for this tenant",
            code="attribute_not_enabled",
            field="attribute_key",
        )
    return config


def _enforce_self_edit_policy(
    requesting_user: RequestingUser,
    target_user_id: str,
    config: dict,
) -> None:
    """Enforce the locking + allow_users_edit_profile rules for one write.

    Admins (admin / super_admin) bypass both checks. Users acting on
    themselves are subject to:
      - the tenant ``allow_users_edit_profile`` setting
      - the per-attribute ``locked_for_users`` flag.
    """
    if requesting_user["role"] in ("admin", "super_admin"):
        return

    if requesting_user["id"] != target_user_id:
        # Non-admin acting on someone else is always forbidden here -- the
        # caller layer should not have routed this request to us.
        raise ForbiddenError(
            message="Cannot edit another user's profile",
            code="forbidden",
        )

    if not can_user_edit_profile(requesting_user["tenant_id"]):
        raise ForbiddenError(
            message="Profile editing is disabled by your organization",
            code="profile_editing_disabled",
        )

    if config.get("locked_for_users"):
        raise ForbiddenError(
            message="This attribute is locked. Only an administrator can change it.",
            code="attribute_locked",
        )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def list_user_attributes(
    requesting_user: RequestingUser,
    user_id: str,
) -> list[dict]:
    """Return canonical attribute rows for ``user_id``.

    Authorization: a user can read their own attributes; admins can read
    any user in their tenant.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    if requesting_user["id"] != user_id and requesting_user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Cannot read another user's attributes",
            code="forbidden",
        )
    return database.user_attributes.list_attributes(requesting_user["tenant_id"], user_id)


def get_user_attribute(
    requesting_user: RequestingUser,
    user_id: str,
    attribute_key: str,
) -> dict | None:
    """Return one canonical attribute row, or ``None`` if not set."""
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    if requesting_user["id"] != user_id and requesting_user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Cannot read another user's attributes",
            code="forbidden",
        )
    _require_known_attribute(attribute_key)
    return database.user_attributes.get_attribute(
        requesting_user["tenant_id"], user_id, attribute_key
    )


def list_user_idp_attributes(
    requesting_user: RequestingUser,
    user_id: str,
) -> list[dict]:
    """Return all IdP-mirror snapshot rows for ``user_id``.

    Authorization: admin / super_admin only. The IdP-mirror panel is not
    surfaced on self-service; users only see canonical values.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    if requesting_user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )
    return database.user_idp_attributes.list_attributes(requesting_user["tenant_id"], user_id)


# ---------------------------------------------------------------------------
# Writes (user / admin)
# ---------------------------------------------------------------------------


def set_user_attribute(
    requesting_user: RequestingUser,
    user_id: str,
    attribute_key: str,
    value: str,
) -> dict:
    """Set or update one canonical attribute value.

    Validates the attribute is enabled for the tenant, that the requester
    is allowed to edit (lock + tenant policy), and that the value passes
    per-type serialization. Emits ``user_profile_updated`` with
    ``cause=self_edit`` or ``cause=admin_edit`` when the value changes.
    """
    tenant_id = requesting_user["tenant_id"]

    _require_known_attribute(attribute_key)
    config = _require_enabled(tenant_id, attribute_key)
    _enforce_self_edit_policy(requesting_user, user_id, config)

    serialized = serialize(attribute_key, value)

    existing = database.user_attributes.get_attribute(tenant_id, user_id, attribute_key)
    old_value = existing["value"] if existing else None

    # Provenance is role-based, not identity-based: a value set by an admin /
    # super_admin is 'admin'-sourced (authority-grade, always emitted to SPs),
    # even when the admin edits their own profile. A value a non-admin sets on
    # themselves is 'self'-sourced (spoofable, withheld from SP assertions
    # unless the tenant opts the attribute in). This deliberately differs from
    # ``cause`` below, which records who acted on whom for the audit trail.
    is_admin = requesting_user["role"] in ("admin", "super_admin")
    source = "admin" if is_admin else "self"

    row = database.user_attributes.upsert_attribute(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        attribute_key=attribute_key,
        value=serialized,
        source=source,
    )

    if old_value != serialized:
        cause = "self_edit" if requesting_user["id"] == user_id else "admin_edit"
        action = "added" if old_value is None else "updated"
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_profile_updated",
            metadata={
                "cause": cause,
                "idp_id": None,
                # Record only the action per attribute key. The raw before/after
                # values are deliberately omitted to keep PII (phone, address,
                # employee ID, etc.) out of the audit event stream and any
                # downstream event-log exports.
                "changes": {attribute_key: action},
            },
        )

    # If this user is in the force-profile-completion flow, re-evaluate
    # the gate. Once every required+unlocked attribute has a value the
    # flag clears automatically.
    _maybe_clear_force_profile_completion(tenant_id, user_id)

    return row


def clear_user_attribute(
    requesting_user: RequestingUser,
    user_id: str,
    attribute_key: str,
) -> bool:
    """Delete one canonical attribute row.

    Returns True if a row was deleted, False if there was nothing to
    delete. Lock and tenant policy apply identically to ``set``.
    """
    tenant_id = requesting_user["tenant_id"]

    _require_known_attribute(attribute_key)
    # Don't require enabled for clear -- if a tenant turned off an attribute
    # an admin should still be able to scrub stale values. We still need
    # the config row to know the lock state though.
    config = database.tenant_attribute_config.get_config(tenant_id, attribute_key) or {
        "locked_for_users": False,
    }
    _enforce_self_edit_policy(requesting_user, user_id, config)

    existing = database.user_attributes.get_attribute(tenant_id, user_id, attribute_key)
    if existing is None:
        return False

    rows_affected = database.user_attributes.delete_attribute(tenant_id, user_id, attribute_key)
    if rows_affected == 0:
        return False

    cause = "self_edit" if requesting_user["id"] == user_id else "admin_edit"
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_profile_updated",
        metadata={
            "cause": cause,
            "idp_id": None,
            # See set_user_attribute: action only, no PII values.
            "changes": {attribute_key: "cleared"},
        },
    )
    return True


# ---------------------------------------------------------------------------
# Bulk form-driven updates (used by web routers)
# ---------------------------------------------------------------------------


def apply_attribute_form_updates(
    requesting_user: RequestingUser,
    target_user_id: str,
    form_data: dict[str, str | None],
    *,
    enforce_user_lock: bool,
) -> dict:
    """Apply a form's worth of attribute changes for one user.

    Iterates the tenant's enabled attribute config and, for each key
    present in ``form_data``, either ``set_user_attribute`` (non-empty
    trimmed value) or ``clear_user_attribute`` (empty / ``None``). Keys
    not present in ``form_data`` are left alone -- this matches the
    "only fields the form submitted are touched" semantics both router
    callers relied on.

    Args:
        requesting_user: the authenticated caller (auth happens in the
            underlying ``set_user_attribute`` / ``clear_user_attribute``).
        target_user_id: the user whose canonical row is being mutated.
        form_data: ``{attribute_key: raw_value_or_None}``. Empty strings
            and ``None`` both clear the value; trimmed non-empty strings
            set it.
        enforce_user_lock: when ``True`` (the self-service path), skip
            keys whose tenant config has ``locked_for_users=True``. When
            ``False`` (the admin path), every enabled key is writable.
            Admin callers still get the underlying service's
            ``ForbiddenError`` if they aren't actually an admin -- this
            flag is a UI affordance, not an authorization decision.

    Returns:
        ``{"error_code": str | None, "set_keys": list[str],
           "cleared_keys": list[str], "skipped_locked_keys": list[str]}``

        ``error_code`` is ``"invalid_<key>"`` for the first per-key
        validation failure, ``"save_failed"`` for any other
        ``ServiceError``, ``"user_not_found"`` if a key write raised
        ``NotFoundError`` (so the router can render the right banner),
        or ``None`` on success.

    Both web routers (``account.py``, ``users/detail.py``) translate
    their ``request.form()`` into ``form_data`` and use the result to
    pick the right redirect target.
    """
    # track_activity here as well as in the underlying set/clear -- the
    # double-call is idempotent and the compliance checker requires every
    # public service function that takes a RequestingUser to call it.
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Use the settings service (not the database layer directly) so the same
    # authz / activity tracking applies as if the router were calling it.
    # Imported via the package (not the submodule) so tests that mock
    # ``services.settings.list_tenant_attribute_config`` see the patch.
    # Lazy to avoid a services.users <-> services.settings cycle at package
    # import time.
    from services import settings as settings_service

    config_rows = settings_service.list_tenant_attribute_config(requesting_user)

    set_keys: list[str] = []
    cleared_keys: list[str] = []
    skipped_locked_keys: list[str] = []
    error_code: str | None = None

    for cfg in config_rows:
        if not cfg.get("enabled"):
            continue
        key = cfg["attribute_key"]
        if key not in form_data:
            continue
        if enforce_user_lock and cfg.get("locked_for_users"):
            skipped_locked_keys.append(key)
            continue

        raw_value = form_data[key]
        raw = "" if raw_value is None else str(raw_value).strip()
        try:
            if raw:
                set_user_attribute(requesting_user, target_user_id, key, raw)
                set_keys.append(key)
            else:
                clear_user_attribute(requesting_user, target_user_id, key)
                cleared_keys.append(key)
        except NotFoundError:
            # Caller should render a "user not found" banner -- fall through
            # to ``error_code`` so the loop still completes the rest of the
            # keys (idempotent ops won't re-fail).
            error_code = error_code or "user_not_found"
        except (ValidationError, ValueError):
            # ValueError covers ``AttributeValueError`` raised by the registry
            # serializer (e.g. bad ISO country code, value over max_length).
            # Both are per-key input failures from the user's perspective.
            error_code = error_code or f"invalid_{key}"
        except ServiceError:
            # Any other service-layer failure (ForbiddenError, etc.) surfaces
            # as a generic save failure rather than leaking the cause.
            error_code = error_code or "save_failed"

    return {
        "error_code": error_code,
        "set_keys": set_keys,
        "cleared_keys": cleared_keys,
        "skipped_locked_keys": skipped_locked_keys,
    }


# ---------------------------------------------------------------------------
# Writes (IdP mirror)
# ---------------------------------------------------------------------------


def apply_idp_attributes(
    tenant_id: str,
    user_id: str,
    idp_id: str,
    attributes: dict[str, str],
    *,
    actor_user_id: str,
) -> None:
    """Apply an IdP login's attribute set to both storage spaces.

    1. Validate ``idp_id`` belongs to ``tenant_id``.
    2. Replace the user's IdP-mirror snapshot for that IdP atomically.
    3. For each (key, value) where the tenant has ``enabled=true`` AND
       ``mirror_from_idp=true``, upsert ``user_attributes`` with the
       serialized value.
    4. Emit a single ``user_profile_updated`` event with
       ``cause=idp_mirror`` when one or more canonical values changed.

    Both writes happen inside one ``database.session()`` so observers
    never see a partial state.

    Unknown attribute keys (not in the standard registry) are dropped
    silently from both writes -- the per-IdP attribute_mapping is
    expected to filter, but defence in depth never hurts.
    """
    # 1. Tenant-IdP ownership check (defence in depth at service boundary;
    # the per-IdP attribute_mapping JSON is supposed to be in this tenant
    # already, but we verify before writing rows that reference idp_id).
    idp = database.saml.get_identity_provider(tenant_id, idp_id)
    if idp is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Filter to known attribute keys and serialize values up front so any
    # validation error rolls back nothing (we haven't written yet).
    serialized_attributes: dict[str, str] = {}
    for key, raw in attributes.items():
        if not is_standard_attribute(key):
            continue
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            # Empty values are dropped (treated as "IdP no longer sends this").
            continue
        try:
            serialized_attributes[key] = serialize(key, raw)
        except (ValueError, ValidationError):
            # Skip malformed values silently -- the IdP login flow must not
            # fail because one attribute is wrong. The mirror table simply
            # won't carry it. Future iterations may surface a warning.
            continue

    changes: dict[str, str] = {}

    with database.session(tenant_id=tenant_id) as cur:
        # Read tenant_attribute_config and the existing canonical snapshot
        # INSIDE the transaction so the change-diff and the mirror-write set
        # both reflect the row state at the moment of the write. Reading them
        # before the transaction begins would let a concurrent admin toggle
        # ``mirror_from_idp`` (or another writer edit ``user_attributes``)
        # sneak between the read and the write, producing a stale diff in the
        # emitted ``user_profile_updated`` event.
        cur.execute(
            """
            select attribute_key, enabled, mirror_from_idp
              from tenant_attribute_config
             where tenant_id = %(tenant_id)s
            """,
            {"tenant_id": tenant_id},
        )
        config_rows = cur.fetchall()
        config_by_key = {r["attribute_key"]: r for r in config_rows}

        mirror_writes: dict[str, str] = {}
        for key, value in serialized_attributes.items():
            cfg = config_by_key.get(key)
            if cfg and cfg.get("enabled") and cfg.get("mirror_from_idp"):
                mirror_writes[key] = value

        # Snapshot of existing canonical values BEFORE the write, so the
        # change-diff is built from the same row state we are about to
        # overwrite. We deliberately record only the per-key action and not the
        # raw before/after values: IdP-mirrored attributes include phone,
        # address, employee ID etc., and the audit/event-log stream must not
        # be a PII sink.
        cur.execute(
            """
            select attribute_key, value
              from user_attributes
             where user_id = %(user_id)s
            """,
            {"user_id": user_id},
        )
        existing_rows = {r["attribute_key"]: r["value"] for r in cur.fetchall()}
        for key, new_value in mirror_writes.items():
            old_value = existing_rows.get(key)
            if old_value != new_value:
                changes[key] = "added" if old_value is None else "updated"

        # Replace the IdP-mirror snapshot for this IdP.
        if serialized_attributes:
            cur.execute(
                """
                delete from user_idp_attributes
                where user_id = %(user_id)s
                  and idp_id = %(idp_id)s
                  and attribute_key <> all(%(keys)s)
                """,
                {
                    "user_id": user_id,
                    "idp_id": idp_id,
                    "keys": list(serialized_attributes.keys()),
                },
            )
        else:
            cur.execute(
                """
                delete from user_idp_attributes
                where user_id = %(user_id)s and idp_id = %(idp_id)s
                """,
                {"user_id": user_id, "idp_id": idp_id},
            )

        for key, value in serialized_attributes.items():
            cur.execute(
                """
                insert into user_idp_attributes (
                    tenant_id, user_id, idp_id, attribute_key, value
                ) values (
                    %(tenant_id)s, %(user_id)s, %(idp_id)s,
                    %(attribute_key)s, %(value)s
                )
                on conflict (user_id, idp_id, attribute_key) do update set
                    value = excluded.value,
                    updated_at = now()
                """,
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "idp_id": idp_id,
                    "attribute_key": key,
                    "value": value,
                },
            )

        # Mirror enabled+mirror_from_idp keys into user_attributes. These are
        # 'idp'-sourced (authority-grade): they always emit to SPs and overwrite
        # any prior 'self'/'admin' provenance, since the IdP is now the writer.
        for key, value in mirror_writes.items():
            cur.execute(
                """
                insert into user_attributes (
                    tenant_id, user_id, attribute_key, value, source
                ) values (
                    %(tenant_id)s, %(user_id)s, %(attribute_key)s, %(value)s, 'idp'
                )
                on conflict (user_id, attribute_key) do update set
                    value = excluded.value,
                    source = excluded.source,
                    updated_at = now()
                """,
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "attribute_key": key,
                    "value": value,
                },
            )

    # Single event for the canonical write set (if anything changed).
    if changes:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_profile_updated",
            metadata={
                "cause": "idp_mirror",
                "idp_id": idp_id,
                "changes": changes,
            },
        )


def scrub_canonical_matches_mirror(
    *,
    tenant_id: str,
    idp_id: str,
    actor_user_id: str,
    user_id: str | None = None,
) -> int:
    """Delete canonical ``user_attributes`` rows whose value still equals an
    IdP's last-mirrored snapshot value.

    Used when a user's relationship to ``idp_id`` ends (the IdP is deleted, or
    the user is disconnected / moved to a different IdP), so attributes that
    only ever flowed in from that IdP stop being emitted in assertions.

    Canonical rows that have diverged from the mirror snapshot (because the
    user or an admin edited them after the mirror write) are left alone, since
    those carry independent provenance. Emits one ``user_profile_updated``
    event per affected user with ``cause: idp_disconnect_scrub`` listing the
    cleared keys. Returns the total number of canonical rows deleted.

    When ``user_id`` is given the scrub is confined to that single user (the
    per-user disconnect path); otherwise every user mirrored from ``idp_id`` is
    scrubbed (the IdP-delete path).
    """
    # Single set-based DELETE ... USING ... RETURNING. A per-(user, key)
    # DELETE would make IdP disconnects O(n*m) round-trips. The set-based form
    # returns the actually-deleted (user_id, attribute_key) pairs so we can
    # group in Python and emit one event per affected user.
    params: dict[str, str] = {"idp_id": idp_id, "tenant_id": tenant_id}
    user_filter = ""
    if user_id is not None:
        user_filter = "and ua.user_id = %(user_id)s"
        params["user_id"] = user_id

    with database.session(tenant_id=tenant_id) as cur:
        cur.execute(
            f"""
            delete from user_attributes ua
            using user_idp_attributes uia
            where ua.user_id = uia.user_id
              and ua.attribute_key = uia.attribute_key
              and ua.value = uia.value
              and uia.idp_id = %(idp_id)s
              and ua.tenant_id = %(tenant_id)s
              {user_filter}
            returning ua.user_id, ua.attribute_key
            """,
            params,
        )
        deleted_rows = cur.fetchall()

    if not deleted_rows:
        return 0

    by_user: dict[str, list[str]] = {}
    for r in deleted_rows:
        by_user.setdefault(str(r["user_id"]), []).append(r["attribute_key"])

    for affected_user_id, keys in by_user.items():
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="user",
            artifact_id=affected_user_id,
            event_type="user_profile_updated",
            metadata={
                "cause": "idp_disconnect_scrub",
                "idp_id": idp_id,
                "cleared_keys": keys,
            },
        )

    return len(deleted_rows)


# ---------------------------------------------------------------------------
# Required-field enforcement (Iteration 7)
# ---------------------------------------------------------------------------


def compute_missing_required(tenant_id: str, user_id: str) -> list[tuple[str, bool]]:
    """Return the list of required+enabled attributes the user is missing.

    Each entry is ``(attribute_key, locked)`` where ``locked`` reflects
    the tenant's ``locked_for_users`` flag for that attribute. Callers
    decide whether to act on locked-vs-unlocked separately:

    * Dashboard banner / force-completion gate: filter to ``locked=False``
      (the user can only act on those).
    * Admin Todo view: surfaces both.

    The function is a pure read (no event log, no activity tracking) so
    it is safe to call inside hot paths such as the dashboard render or
    a middleware-level gate. The caller is responsible for any audit
    surfacing.
    """
    # Single pass over config_rows: collect required+enabled keys and a
    # ``locked_for_users`` lookup for every config row in one traversal.
    # The locked map covers every row (not just required ones) because a
    # required key's locked flag is what the caller filters on.
    config_rows = database.tenant_attribute_config.list_config(tenant_id)
    required_keys: list[str] = []
    locked_by_key: dict[str, bool] = {}
    for row in config_rows:
        key = row["attribute_key"]
        locked_by_key[key] = bool(row.get("locked_for_users"))
        if row.get("enabled") and row.get("required"):
            required_keys.append(key)

    if not required_keys:
        return []

    existing_rows = database.user_attributes.list_attributes(tenant_id, user_id)
    present_keys = {
        row["attribute_key"]
        for row in existing_rows
        if row.get("value") and str(row["value"]).strip()
    }

    return [
        (key, locked_by_key.get(key, False)) for key in required_keys if key not in present_keys
    ]


def _maybe_clear_force_profile_completion(tenant_id: str, user_id: str) -> None:
    """Clear ``force_profile_completion`` if the user-fixable gate is satisfied.

    Called from ``set_user_attribute`` after each successful upsert. The
    flag is cleared only when every required+enabled+UNLOCKED attribute
    has a value (locked fields are admin-only and cannot block the user
    from leaving the gated flow).
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user or not user.get("force_profile_completion"):
        return
    missing = compute_missing_required(tenant_id, user_id)
    user_fixable_missing = [key for key, locked in missing if not locked]
    if not user_fixable_missing:
        database.users.set_force_profile_completion(tenant_id, user_id, False)


def list_users_with_missing_required(
    requesting_user: RequestingUser,
) -> list[dict]:
    """Return one row per (user, missing-required-attribute) pair.

    Authorization: admin / super_admin only.

    Returns a list of dicts (admin Todo view payload) shaped as:

        {
            "user_id": str,
            "first_name": str,
            "last_name": str,
            "email": str | None,
            "attribute_key": str,
            "locked": bool,
            "force_profile_completion": bool,
        }

    The query is one DB round-trip; callers can group/filter in
    application code. Service users and inactivated/anonymized users are
    excluded by the database query.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    track_activity(tenant_id, requesting_user["id"])

    rows = database.user_attributes.list_missing_required_for_tenant(tenant_id)
    if not rows:
        return []

    # Fetch force_profile_completion flag per unique user in a single query
    # to keep this O(unique users) rather than O(rows).
    user_ids = list({str(r["user_id"]) for r in rows})
    flag_rows = database.fetchall(
        tenant_id,
        """
        select id, force_profile_completion
          from users
         where id = any(:ids)
        """,
        {"ids": user_ids},
    )
    flag_by_user = {str(r["id"]): bool(r["force_profile_completion"]) for r in flag_rows}

    return [
        {
            "user_id": str(r["user_id"]),
            "first_name": r["first_name"],
            "last_name": r["last_name"],
            "email": r["email"],
            "attribute_key": r["attribute_key"],
            "locked": bool(r["locked_for_users"]),
            "force_profile_completion": flag_by_user.get(str(r["user_id"]), False),
        }
        for r in rows
    ]


def bulk_set_force_profile_completion(
    requesting_user: RequestingUser,
    user_ids: list[str],
) -> dict:
    """Flag selected users for forced profile completion.

    Authorization: admin / super_admin only. For each candidate user, the
    flag is set ONLY if every missing required attribute on that user is
    unlocked. If any missing attribute is locked (admin-only), the user
    is skipped (a force-completion redirect would loop forever because
    the user can't fix the locked field themselves).

    Emits ``user_force_profile_completion_set`` per user flagged.

    Returns:
        ``{"flagged": list[str], "skipped_locked": list[str], "skipped_complete": list[str]}``

        - ``flagged`` -- users newly flagged.
        - ``skipped_locked`` -- users with at least one missing required
          LOCKED attribute (no-op; the user couldn't escape the gate).
        - ``skipped_complete`` -- users who had nothing missing at all
          (no-op; nothing to force).
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    # Pre-flight: every user_id must belong to the requesting tenant.
    # RLS would silently classify a foreign UUID as ``skipped_complete``;
    # we surface it as a 404 instead so the audit log never references
    # users outside the actor's tenant. One round-trip via ANY(:ids).
    if user_ids:
        found_rows = database.fetchall(
            tenant_id,
            "select id from users where id = any(:ids)",
            {"ids": user_ids},
        )
        found_ids = {str(r["id"]) for r in found_rows}
        missing_ids = [uid for uid in user_ids if uid not in found_ids]
        if missing_ids:
            raise NotFoundError(f"User(s) not found: {', '.join(missing_ids)}")

    flagged: list[str] = []
    skipped_locked: list[str] = []
    skipped_complete: list[str] = []

    for user_id in user_ids:
        missing = compute_missing_required(tenant_id, user_id)
        if not missing:
            skipped_complete.append(user_id)
            continue
        if any(locked for _key, locked in missing):
            skipped_locked.append(user_id)
            continue
        database.users.set_force_profile_completion(tenant_id, user_id, True)
        flagged.append(user_id)
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_force_profile_completion_set",
            metadata={
                "missing_keys": [key for key, _locked in missing],
            },
        )

    return {
        "flagged": flagged,
        "skipped_locked": skipped_locked,
        "skipped_complete": skipped_complete,
    }


# ---------------------------------------------------------------------------
# Public re-exports for the registry helper used in tests
# ---------------------------------------------------------------------------


# Convenience for callers that want to introspect registry shape without
# importing the constants module directly.
__all__ = [
    "ATTRIBUTES_BY_KEY",
    "apply_attribute_form_updates",
    "apply_idp_attributes",
    "bulk_set_force_profile_completion",
    "clear_user_attribute",
    "compute_missing_required",
    "get_user_attribute",
    "list_user_attributes",
    "list_user_idp_attributes",
    "list_users_with_missing_required",
    "set_user_attribute",
]
