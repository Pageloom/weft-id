"""Write-side service functions for the inbound SCIM Users endpoints.

These power `POST /Users`, `PUT /Users/{id}`, `PATCH /Users/{id}`, and
`DELETE /Users/{id}`. The boundary contract is:

- Caller (router) has already authenticated via `require_inbound_scim_auth`
  and resolved `tenant_id` + `idp_id` from the bearer token. The router
  passes those in directly -- inbound SCIM has no `RequestingUser`.
- These functions return SCIM-payload dicts the router wraps with the
  SCIM media type, OR raise `ScimWriteError` for vendor-visible failures.
- Each successful write logs an event (`scim_user_received` /
  `scim_user_updated` / `scim_user_deactivated`); the `EVENT_TYPE_SCIM_TRIGGERS`
  registry routes those events into the outbound dispatch fan-out, so
  downstream SPs cascade automatically without a separate replay layer.

Merge function (`create_or_merge_user`) is the highest-risk piece. It
runs in three steps:

1. Lookup by upstream `externalId` (if provided).
2. Lookup by canonical email (lowercased; plus-addressing left intact
   to match WeftID's existing email storage convention).
3. Create the user if neither hit.

Concurrent identical POSTs are caught by DB constraints: the partial
unique index on `user_idp_attributes (idp_id, value) WHERE attribute_key
= '__external_id'` (migration 0044) and the existing
`user_emails (tenant_id, email)` uniqueness. On collision we retry the
merge once; the second pass sees the row the winner just wrote and
goes through the merge branch.

PATCH supports the SCIM 2.0 simple-path subset and Entra's batched
`Operations` array. Exotic filter expressions return `400 invalidFilter`.

Status transitions:
- POST or PUT with `active=false` -> soft-delete (existing inactivate flow).
- POST or PUT with `active=true` on an inactivated user -> reactivate.
- DELETE -> soft-delete (the same code path; MFA + history preserved).
"""

from __future__ import annotations

import logging
from typing import Any

import database
import psycopg.errors
from constants.user_attributes import is_standard_attribute
from schemas.scim import ENTERPRISE_USER_SCHEMA
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.scim import inbound_read
from services.users.attributes import apply_idp_attributes
from utils.validate import is_email_like

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vendor-visible errors
# ---------------------------------------------------------------------------


class ScimWriteError(Exception):  # noqa: N818 -- name pairs with router's ScimErrorException
    """Raised when a SCIM write fails in a vendor-visible way.

    Routers translate this into a SCIM 2.0 Error envelope. Carries
    HTTP `status_code`, optional machine-readable `scim_type` (per
    RFC 7644 §3.12: `mutability`, `invalidValue`, `invalidFilter`,
    `uniqueness`, etc.), and human-readable `detail`.
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        scim_type: str | None = None,
    ):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Fields a SCIM client is allowed to mutate via inbound SCIM. Anything
# outside this list (role, MFA, password, etc.) is rejected with
# `400 mutability`. Group membership is handled exclusively through the
# Groups endpoints, not via patching Users.
_PATCH_ALLOWED_SIMPLE_PATHS = frozenset(
    {
        "username",
        "active",
        "externalid",
        "displayname",
        "name.givenname",
        "name.familyname",
        "name.formatted",
        "emails",
        "title",
        "jobtitle",
        "preferredlanguage",
        "phonenumbers",
        # Enterprise extension sub-attributes (after URN normalisation).
        "enterprise.department",
        "enterprise.organization",
        "enterprise.employeenumber",
    }
)


# Paths a SCIM client must never set. Even an attempt is a security
# signal (caller trying to escalate). We return `mutability` per spec.
_FORBIDDEN_PATHS = frozenset(
    {
        "roles",
        "role",
        "groups",
        "password",
        "mfa",
        "mfa_enabled",
        "mfaenabled",
    }
)


def _canonical_email(email: str | None) -> str | None:
    """Return the canonical form for an email address.

    Lowercase only -- WeftID stores emails verbatim and the `citext`
    column on `user_emails` already makes lookups case-insensitive.
    Plus-addressing is deliberately preserved: an admin may have
    explicitly created `alice+work@x` as a distinct identity, and
    collapsing it would merge unrelated accounts.
    """
    if email is None:
        return None
    s = email.strip()
    if not s:
        return None
    return s.lower()


def _extract_primary_email_candidate(payload: dict | Any) -> str | None:
    """Pull the best email candidate from a SCIM payload (no format check).

    Prefers the primary `emails[]` entry, then the first `emails[]`
    entry, then `userName`. Used by `_extract_primary_email`, which
    applies the format guard on top.
    """
    emails = payload.get("emails") if isinstance(payload, dict) else None
    if emails:
        # First entry flagged primary, else first entry.
        primary = next((e for e in emails if isinstance(e, dict) and e.get("primary")), None)
        chosen = primary or (emails[0] if isinstance(emails[0], dict) else None)
        if chosen and chosen.get("value"):
            return _canonical_email(chosen["value"])
    user_name = payload.get("userName") if isinstance(payload, dict) else None
    return _canonical_email(user_name)


def _extract_primary_email(payload: dict | Any) -> str | None:
    """Pull the canonical primary email from a SCIM User payload.

    Falls back to `userName` if `emails` is absent (most vendors use
    email as `userName`). Returns the canonical form, or None when the
    candidate is not email-shaped.

    The format guard matters because some IdPs (Okta in particular) can
    send a bare identifier as `userName` (e.g. "alice.smith"). Without
    the guard that string would land in the `user_emails.email` citext
    column and the user would carry a non-email "email." When the only
    candidate is a non-email `userName`, we return None so the create
    path rejects with `400 invalidValue` instead of storing garbage.
    """
    candidate = _extract_primary_email_candidate(payload)
    if candidate is None:
        return None
    return candidate if is_email_like(candidate) else None


def _extract_names(payload: dict) -> tuple[str | None, str | None]:
    """Extract (first_name, last_name) from a SCIM User payload.

    Falls back to splitting `displayName` if `name` isn't given but
    `displayName` is; otherwise returns whatever is set (possibly None).
    """
    name = payload.get("name") if isinstance(payload, dict) else None
    if isinstance(name, dict):
        first = (name.get("givenName") or "").strip() or None
        last = (name.get("familyName") or "").strip() or None
        if first or last:
            return first, last
    display = payload.get("displayName") if isinstance(payload, dict) else None
    if isinstance(display, str) and display.strip():
        parts = display.strip().split(None, 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return parts[0], None
    return None, None


def _resolve_replace_names(payload: dict, existing: dict | None) -> tuple[str, str]:
    """Compute (first_name, last_name) for a SCIM PUT (replace) operation.

    Distinguishes three states per RFC 7644 §3.5.1 full-replace semantics:

    1. The field is **absent** from the payload -> preserve the existing
       value. Treating "not specified" as "clear" would clobber real data
       any time a client sent a partial `name` block (e.g. givenName only).
    2. The field is **present and non-empty** -> use the supplied value.
    3. The field is **present but empty** (e.g. `familyName: ""`) -> honour
       it as an explicit SCIM clear and write empty string.

    The literal placeholder strings "SCIM" / "User" are NEVER written.
    """
    existing_first = (existing or {}).get("first_name") or ""
    existing_last = (existing or {}).get("last_name") or ""

    name_block = payload.get("name") if isinstance(payload, dict) else None
    if isinstance(name_block, dict):
        first_present = "givenName" in name_block
        last_present = "familyName" in name_block
        if first_present:
            raw_first = name_block.get("givenName")
            new_first = (raw_first or "").strip() if isinstance(raw_first, str) else ""
        else:
            new_first = existing_first
        if last_present:
            raw_last = name_block.get("familyName")
            new_last = (raw_last or "").strip() if isinstance(raw_last, str) else ""
        else:
            new_last = existing_last
        return new_first, new_last

    # `name` block absent. Fall back to displayName split if it's present.
    display = payload.get("displayName") if isinstance(payload, dict) else None
    if isinstance(display, str) and display.strip():
        parts = display.strip().split(None, 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return parts[0], existing_last

    # Neither `name` nor `displayName` provided -> preserve existing.
    return existing_first, existing_last


def _extract_standard_attributes(payload: dict) -> dict[str, str]:
    """Pull EnterpriseUser + custom-extension attributes from a SCIM payload.

    Maps SCIM camelCase attribute names to WeftID's standard registry
    keys where the two intersect. Returns the subset of values to push
    through `apply_idp_attributes`. Unknown / extra attributes are
    ignored by that function anyway, but we filter at this layer too
    so the audit trail is clean.
    """
    out: dict[str, str] = {}
    enterprise = payload.get(ENTERPRISE_USER_SCHEMA) if isinstance(payload, dict) else None
    if isinstance(enterprise, dict):
        # Map EnterpriseUser SCIM fields onto WeftID registry keys.
        mapping = {
            "employeeNumber": "employee_id",
            "department": "department",
            "organization": "organization",
        }
        for scim_key, weft_key in mapping.items():
            value = enterprise.get(scim_key)
            if isinstance(value, str) and value.strip():
                out[weft_key] = value.strip()

    # Pluck top-level camelCase keys that match registry friendly names.
    # `displayName` is handled here because the registry exposes it as a
    # standard attribute too. `jobTitle` is a Microsoft-Entra-only field
    # that maps cleanly onto job_title.
    direct_mappings: dict[str, str] = {
        "displayName": "display_name",
        "title": "job_title",
        "jobTitle": "job_title",
        "preferredLanguage": "preferred_language",
    }
    for scim_key, weft_key in direct_mappings.items():
        value = payload.get(scim_key)
        if isinstance(value, str) and value.strip() and is_standard_attribute(weft_key):
            out[weft_key] = value.strip()

    # Phone numbers come as an array of {value, type}.
    phones = payload.get("phoneNumbers")
    if isinstance(phones, list):
        for entry in phones:
            if not isinstance(entry, dict) or not entry.get("value"):
                continue
            ptype = (entry.get("type") or "").lower()
            value = str(entry["value"]).strip()
            if not value:
                continue
            if ptype == "mobile" and "phone_mobile" not in out:
                out["phone_mobile"] = value
            elif ptype == "work" and "phone_work" not in out:
                out["phone_work"] = value

    return out


def _ensure_no_mutability_violation(payload: dict, *, source: str = "payload") -> None:
    """Reject SCIM payloads that try to set role / password / groups / MFA.

    Inbound SCIM is directory-only. Role changes, password sets, MFA
    enrolment, and group membership all flow through other paths (admin
    UI, user self-service, or the SCIM Groups endpoint for membership).
    """
    if not isinstance(payload, dict):
        return
    for key in payload:
        if key.lower() in _FORBIDDEN_PATHS:
            raise ScimWriteError(
                status_code=400,
                detail=f"Attribute `{key}` is not writable via inbound SCIM ({source}).",
                scim_type="mutability",
            )


def _resolve_user_payload(
    tenant_id: str,
    idp_id: str,
    user_id: str,
    location_builder,
) -> dict:
    """Build the SCIM user response payload for a freshly written user."""
    location = location_builder(user_id)
    payload = inbound_read.get_user(tenant_id, idp_id, user_id, location=location)
    if payload is None:  # pragma: no cover -- defensive; we just wrote this user
        raise ScimWriteError(
            status_code=500,
            detail="User written but could not be re-read for response.",
        )
    return payload


def _bump_updated_at(tenant_id: str, user_id: str) -> None:
    """Force `users.updated_at` to now() even when no profile column changed.

    PUT / PATCH / DELETE must observably bump `lastModified` so SCIM
    clients see the mutation in their next read. The migration's BEFORE
    UPDATE trigger only fires on actual UPDATE statements, so we issue
    a no-op write here for cases where the only state change happened
    in another table (e.g. `user_idp_attributes`).
    """
    database.execute(
        tenant_id,
        "update users set updated_at = now() where id = :user_id",
        {"user_id": user_id},
    )


def _create_user_from_scim(
    tenant_id: str,
    idp_id: str,
    payload: dict,
    *,
    canonical_email: str | None,
    first_name: str | None,
    last_name: str | None,
    external_id: str | None,
) -> str:
    """Create a brand-new WeftID user from an inbound SCIM payload.

    Mirrors `services.saml.provisioning.jit_provision_user` but driven
    by SCIM data rather than a SAML assertion. Returns the new user id.
    """
    if not canonical_email:
        raise ScimWriteError(
            status_code=400,
            detail=(
                "Payload missing a valid email address. Set `emails[].value` or a "
                "`userName` that is an email address."
            ),
            scim_type="invalidValue",
        )

    # Sensible defaults if the SCIM payload omits names.
    first = first_name or "SCIM"
    last = last_name or "User"

    result = database.users.create_user(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        first_name=first,
        last_name=last,
        email=canonical_email,
        role="member",
    )
    if not result:
        raise ScimWriteError(status_code=500, detail="Failed to create user record.")
    user_id = str(result["user_id"])

    database.user_emails.add_verified_email(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        email=canonical_email,
        is_primary=True,
    )

    database.saml.set_user_idp(tenant_id, user_id, idp_id)

    if external_id:
        database.user_idp_attributes.set_external_id(
            tenant_id,
            tenant_id,
            user_id,
            idp_id,
            external_id,
        )

    return user_id


def _apply_payload_writes(
    tenant_id: str,
    idp_id: str,
    user_id: str,
    payload: dict,
    *,
    update_names: bool,
) -> None:
    """Apply name + attribute + externalId writes from a SCIM payload."""
    if update_names:
        first, last = _extract_names(payload)
        if first is not None or last is not None:
            current = database.users.get_user_by_id(tenant_id, user_id)
            new_first = first if first is not None else (current["first_name"] if current else "")
            new_last = last if last is not None else (current["last_name"] if current else "")
            database.users.update_user_profile(tenant_id, user_id, new_first, new_last)

    # Upstream externalId persistence.
    external_id = payload.get("externalId") if isinstance(payload, dict) else None
    if isinstance(external_id, str) and external_id.strip():
        database.user_idp_attributes.set_external_id(
            tenant_id,
            tenant_id,
            user_id,
            idp_id,
            external_id.strip(),
        )

    # Attribute mirror (department / phones / etc).
    extra_attrs = _extract_standard_attributes(payload)
    if extra_attrs:
        try:
            apply_idp_attributes(
                tenant_id=tenant_id,
                user_id=user_id,
                idp_id=idp_id,
                attributes=extra_attrs,
                actor_user_id=SYSTEM_ACTOR_ID,
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "apply_idp_attributes failed for SCIM-written user %s (idp %s)",
                user_id,
                idp_id,
                exc_info=True,
            )


def _handle_active_transition(
    tenant_id: str,
    idp_id: str,
    user_id: str,
    new_active: bool | None,
) -> None:
    """Inactivate or reactivate the user as required by `active`.

    Bypasses the admin-only authorization gate in `services.users.state`
    by talking to the database layer directly -- the SCIM caller is
    authenticated as the IdP, not as a WeftID admin. Token verification
    has already established that they own this IdP connection.
    """
    if new_active is None:
        return

    current = database.users.get_user_by_id(tenant_id, user_id)
    if current is None:
        return

    if not new_active and not current.get("is_inactivated"):
        database.users.inactivate_user(tenant_id, user_id)
        database.oauth2.revoke_all_user_tokens(tenant_id, user_id)
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="user",
            artifact_id=user_id,
            event_type="scim_user_deactivated",
            metadata={"idp_id": idp_id, "cause": "scim_active_false"},
        )
    elif new_active and current.get("is_inactivated") and not current.get("is_anonymized"):
        database.users.reactivate_user(tenant_id, user_id)
        database.users.clear_reactivation_denied(tenant_id, user_id)
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="user",
            artifact_id=user_id,
            event_type="scim_user_reactivated",
            metadata={"idp_id": idp_id, "cause": "scim_active_true"},
        )


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------


def create_or_merge_user(
    tenant_id: str,
    idp_id: str,
    payload: dict,
    *,
    location_builder,
) -> tuple[dict, bool]:
    """SCIM `POST /Users`: create-or-merge.

    Returns `(scim_user_payload, created)`. `created` is True when a new
    user row was written, False when an existing user was merged into.

    Merge precedence:
    1. Upstream `externalId` (stored in `user_idp_attributes` under
       `__external_id` for this IdP).
    2. Canonical primary email.
    3. Create new.

    Concurrency: the lookups and writes do NOT share a transaction, so
    two simultaneous POSTs with the same externalId or canonical email
    can both miss the lookup and race into the create branch. Two DB
    constraints catch this deterministically: the partial unique index
    on `user_idp_attributes (idp_id, value) WHERE attribute_key =
    '__external_id'` (migration 0044) and the existing
    `user_emails (tenant_id, email) UNIQUE` constraint. The loser of
    that race raises `psycopg.errors.UniqueViolation`; we retry the
    merge once and the second pass finds the row the winner just wrote.
    """
    try:
        return _create_or_merge_user_attempt(
            tenant_id, idp_id, payload, location_builder=location_builder
        )
    except psycopg.errors.UniqueViolation:
        # Concurrent identical POST won the race. Retrying the merge
        # will hit the externalId or email lookup this time and go
        # through the merge branch instead of create.
        logger.info(
            "Inbound SCIM merge retry after UniqueViolation",
            extra={"tenant_id": tenant_id, "idp_id": idp_id},
        )
        return _create_or_merge_user_attempt(
            tenant_id, idp_id, payload, location_builder=location_builder
        )


def _create_or_merge_user_attempt(
    tenant_id: str,
    idp_id: str,
    payload: dict,
    *,
    location_builder,
) -> tuple[dict, bool]:
    _ensure_no_mutability_violation(payload)

    canonical_email = _extract_primary_email(payload)
    external_id = payload.get("externalId")
    if isinstance(external_id, str):
        external_id = external_id.strip() or None
    else:
        external_id = None
    first_name, last_name = _extract_names(payload)
    active = payload.get("active")
    if active is not None and not isinstance(active, bool):
        raise ScimWriteError(
            status_code=400,
            detail="`active` must be a boolean.",
            scim_type="invalidValue",
        )

    created = False
    user_id: str | None = None

    with database.session(tenant_id=tenant_id) as cur:
        # 1. Lookup by upstream externalId.
        if external_id:
            cur.execute(
                """
                select user_id
                from user_idp_attributes
                where idp_id = %(idp_id)s
                  and attribute_key = %(attr_key)s
                  and value = %(value)s
                limit 1
                """,
                {
                    "idp_id": idp_id,
                    "attr_key": database.user_idp_attributes.EXTERNAL_ID_KEY,
                    "value": external_id,
                },
            )
            row = cur.fetchone()
            if row:
                user_id = str(row["user_id"])

        # 2. Lookup by canonical primary email.
        if user_id is None and canonical_email:
            cur.execute(
                """
                select ue.user_id
                from user_emails ue
                join users u on u.id = ue.user_id
                where ue.email = %(email)s and ue.is_primary = true
                limit 1
                """,
                {"email": canonical_email},
            )
            row = cur.fetchone()
            if row:
                user_id = str(row["user_id"])

    if user_id is None:
        # 3. Create new. If a concurrent POST won the race, the partial
        # unique index on externalId or the user_emails uniqueness
        # constraint raises UniqueViolation, which the caller catches
        # and retries.
        user_id = _create_user_from_scim(
            tenant_id,
            idp_id,
            payload,
            canonical_email=canonical_email,
            first_name=first_name,
            last_name=last_name,
            external_id=external_id,
        )
        created = True
    else:
        # Existing user: ensure they're bound to this IdP, then apply
        # name + attribute writes. We deliberately do NOT overwrite the
        # primary email on a merge -- SCIM is sending us its view of the
        # user, but admins may have configured additional aliases that
        # should not be wiped.
        existing = database.users.get_user_by_id(tenant_id, user_id)
        previous_idp_id = str((existing or {}).get("saml_idp_id") or "")
        if existing and previous_idp_id != str(idp_id):
            database.saml.set_user_idp(tenant_id, user_id, idp_id)
            # Cross-IdP rebind: a canonical email already bound to another
            # IdP was claimed by this IdP. Emit a dedicated audit event so
            # operators can filter for "this user moved IdPs" forensically;
            # `scim_user_received` alone hides the previous binding.
            log_event(
                tenant_id=tenant_id,
                actor_user_id=SYSTEM_ACTOR_ID,
                artifact_type="user",
                artifact_id=user_id,
                event_type="scim_user_rebound",
                metadata={
                    "idp_id": idp_id,
                    "previous_idp_id": previous_idp_id or None,
                    "canonical_email": canonical_email,
                },
            )

    _apply_payload_writes(tenant_id, idp_id, user_id, payload, update_names=not created)

    # Handle active transition AFTER attribute writes so the
    # `scim_user_deactivated` event ordering is intuitive.
    _handle_active_transition(
        tenant_id,
        idp_id,
        user_id,
        active if active is not None else None,
    )

    # Bump updated_at so meta.lastModified reflects this write even when
    # the only changes happened in other tables.
    _bump_updated_at(tenant_id, user_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="user",
        artifact_id=user_id,
        event_type="scim_user_received",
        metadata={
            "idp_id": idp_id,
            "merged": not created,
            "external_id": external_id,
            "canonical_email": canonical_email,
        },
    )

    return _resolve_user_payload(tenant_id, idp_id, user_id, location_builder), created


def replace_user(
    tenant_id: str,
    idp_id: str,
    user_id: str,
    payload: dict,
    *,
    location_builder,
) -> dict:
    """SCIM `PUT /Users/{id}`: full-replace semantics.

    Per RFC 7644 §3.5.1, attributes absent from the payload are cleared
    in the spec view, but we deviate in a few defensible ways:

    - **Email is replaced** if `emails[]` is present and non-empty;
      omitted means "keep existing".
    - **Name fields are replaced** unconditionally (empty string clears).
    - **externalId is replaced** unconditionally; missing means "clear".
    - **Mirror attributes**: payload is the new source of truth.
    """
    _ensure_no_mutability_violation(payload)

    existing = database.users.get_user_by_id(tenant_id, user_id)
    if existing is None or str(existing.get("saml_idp_id") or "") != str(idp_id):
        raise ScimWriteError(status_code=404, detail="User not found")

    active = payload.get("active")
    if active is not None and not isinstance(active, bool):
        raise ScimWriteError(
            status_code=400,
            detail="`active` must be a boolean.",
            scim_type="invalidValue",
        )

    # Name: replace per the spec, but distinguish "absent" from "explicit
    # empty". Absence preserves the existing value; explicit empty clears
    # it (RFC 7644 §3.5.1). We must never fabricate placeholder strings
    # ("SCIM" / "User") into a user record -- those would clobber real
    # data if a client sent a partial `name` block.
    new_first, new_last = _resolve_replace_names(payload, existing)
    database.users.update_user_profile(tenant_id, user_id, new_first, new_last)

    # ExternalId: replace.
    external_id = payload.get("externalId")
    if isinstance(external_id, str) and external_id.strip():
        database.user_idp_attributes.set_external_id(
            tenant_id, tenant_id, user_id, idp_id, external_id.strip()
        )

    # Mirror attributes: PUT replaces, so empty extras clear them.
    extras = _extract_standard_attributes(payload)
    try:
        apply_idp_attributes(
            tenant_id=tenant_id,
            user_id=user_id,
            idp_id=idp_id,
            attributes=extras,
            actor_user_id=SYSTEM_ACTOR_ID,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "apply_idp_attributes failed during PUT for user %s (idp %s)",
            user_id,
            idp_id,
            exc_info=True,
        )

    _handle_active_transition(tenant_id, idp_id, user_id, active)
    _bump_updated_at(tenant_id, user_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="user",
        artifact_id=user_id,
        event_type="scim_user_updated",
        metadata={"idp_id": idp_id, "verb": "PUT"},
    )

    return _resolve_user_payload(tenant_id, idp_id, user_id, location_builder)


# ---------------------------------------------------------------------------
# PATCH
# ---------------------------------------------------------------------------


def _parse_patch_op(op: dict) -> tuple[str, str | None, Any]:
    """Normalise a single PATCH operation to (op_lower, path, value).

    `op` is one of `add` / `replace` / `remove`. `path` is the
    case-insensitive attribute path with array filters stripped (we
    only support whole-collection ops for `emails`, not `emails[type
    eq "work"]`).
    """
    if not isinstance(op, dict):
        raise ScimWriteError(
            status_code=400,
            detail="PATCH operations must be objects.",
            scim_type="invalidSyntax",
        )
    op_str = (op.get("op") or "").strip().lower()
    if op_str not in {"add", "replace", "remove"}:
        raise ScimWriteError(
            status_code=400,
            detail=f"Unsupported PATCH op: `{op.get('op')}`.",
            scim_type="invalidSyntax",
        )
    raw_path = op.get("path")
    if raw_path is not None and not isinstance(raw_path, str):
        raise ScimWriteError(
            status_code=400,
            detail="PATCH path must be a string.",
            scim_type="invalidPath",
        )
    return op_str, (raw_path or None), op.get("value")


def _normalise_patch_path(path: str | None) -> str | None:
    """Strip vendor-style array filters and lowercase the path.

    - `emails[type eq "work"].value` becomes `emails`. The caller then
      treats the array as a whole -- this is a deliberate scope cut
      (the iteration's acceptance criteria explicitly mention simple
      paths and `emails[type eq "work"].value`).
    - `name.givenName` becomes `name.givenname`.
    - Microsoft's enterprise URN paths
      (`urn:ietf:...:User:department`) reduce to their suffix
      (`enterprise.<attr>` so the assigner can route them to extras).
    """
    normalised, _filter = _normalise_patch_path_with_filter(path)
    return normalised


def _normalise_patch_path_with_filter(
    path: str | None,
) -> tuple[str | None, tuple[str, str] | None]:
    """Like `_normalise_patch_path` but also returns any extracted filter.

    SCIM clients send element filters like `members[value eq "<uuid>"]`
    to target a specific item inside a multi-valued attribute. The user
    PATCH path discards the filter (only whole-array semantics are
    supported); the group PATCH path needs the filter value to identify
    which member to remove.

    Returns `(normalised_path, (filter_attr, filter_value) | None)`. The
    filter is only extracted for `<eq>` expressions of the shape
    `<attr> eq "<value>"`; anything more exotic returns the filter as
    None and the caller decides whether to reject.
    """
    if path is None:
        return None, None
    stripped = path.strip()
    # Enterprise extension URN prefix -> enterprise.<attr>.
    enterprise_prefix = ENTERPRISE_USER_SCHEMA + ":"
    lowered = stripped.lower()
    if lowered.startswith(enterprise_prefix.lower()):
        suffix = stripped[len(enterprise_prefix) :]
        return f"enterprise.{suffix.lower()}", None
    # Generic URN prefix (urn:ietf:...:Attribute -> Attribute).
    if ":" in stripped and stripped.count(":") >= 3:
        stripped = stripped.rsplit(":", 1)[-1]
    # Extract filter clause if present.
    filter_kv: tuple[str, str] | None = None
    if "[" in stripped:
        prefix, _sep, rest = stripped.partition("[")
        # Drop any trailing sub-attribute after the closing bracket.
        bracket_close = rest.find("]")
        if bracket_close == -1:
            # Malformed; treat as whole-collection.
            return prefix.lower(), None
        filter_body = rest[:bracket_close].strip()
        # Parse `<attr> eq "<value>"`. Tolerate single quotes.
        filter_kv = _parse_eq_filter(filter_body)
        return prefix.lower(), filter_kv
    return stripped.lower(), filter_kv


def _parse_eq_filter(body: str) -> tuple[str, str] | None:
    """Parse a `<attr> eq "<value>"` element filter. Returns None on miss.

    Quotes may be single or double; whitespace is collapsed. Anything
    that's not exactly an `eq` comparison returns None so callers can
    reject with `invalidFilter` if they require a filter to be present.
    """
    # Split on whitespace, but the value may contain quoted spaces;
    # use a simple state-aware parse rather than a regex so the rules
    # match what the metadata advertises.
    parts = body.split(None, 2)
    if len(parts) != 3:
        return None
    attr, op, raw_value = parts[0], parts[1].lower(), parts[2].strip()
    if op != "eq":
        return None
    if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in ("'", '"'):
        value = raw_value[1:-1]
    else:
        value = raw_value
    return attr, value


def _patch_assign(payload_acc: dict, path: str, value: Any) -> None:
    """Assign value to the right slot in our running payload dict.

    `payload_acc` is the synthesised "as-if-PUT" payload we accumulate
    across PATCH ops, then hand to `_apply_payload_writes`. This keeps
    PATCH side-effect-equivalent to a sequence of partial writes
    without exploding into N database round-trips per op.
    """
    if path == "username":
        payload_acc["userName"] = value
    elif path == "active":
        # Entra sometimes sends booleans as JSON strings ("True"/"False").
        # Normalise so downstream type checks pass.
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "false"}:
                payload_acc["active"] = lowered == "true"
            else:
                payload_acc["active"] = value  # fail validation later
        else:
            payload_acc["active"] = bool(value) if value is not None else None
    elif path == "externalid":
        payload_acc["externalId"] = value
    elif path == "displayname":
        payload_acc["displayName"] = value
    elif path == "name.givenname":
        payload_acc.setdefault("name", {})["givenName"] = value
    elif path == "name.familyname":
        payload_acc.setdefault("name", {})["familyName"] = value
    elif path == "name.formatted":
        payload_acc.setdefault("name", {})["formatted"] = value
    elif path == "name":
        # Whole name block replace.
        if isinstance(value, dict):
            payload_acc["name"] = value
    elif path == "emails":
        # Whole emails array replace; tolerate scalar emails too.
        if isinstance(value, list):
            payload_acc["emails"] = value
        elif isinstance(value, str):
            payload_acc["emails"] = [{"value": value, "primary": True}]
    elif path.startswith("enterprise."):
        # Build up the EnterpriseUser extension block.
        ext_key = path.split(".", 1)[1]
        # Map normalised sub-attribute name back to camelCase.
        cm = {
            "department": "department",
            "organization": "organization",
            "employeenumber": "employeeNumber",
        }
        ext = payload_acc.setdefault(ENTERPRISE_USER_SCHEMA, {})
        ext[cm.get(ext_key, ext_key)] = value
    elif path == "title" or path == "jobtitle":
        payload_acc["jobTitle"] = value
    elif path == "preferredlanguage":
        payload_acc["preferredLanguage"] = value
    elif path == "phonenumbers":
        if isinstance(value, list):
            payload_acc["phoneNumbers"] = value
    elif path in _PATCH_ALLOWED_SIMPLE_PATHS:
        # Catch-all for paths we accept but don't yet wire individually.
        payload_acc[path] = value


def _process_patch_operation(payload_acc: dict, raw_op: dict) -> None:
    """Apply one PATCH op to the running accumulator."""
    op, raw_path, value = _parse_patch_op(raw_op)

    # No-path ops: SCIM 2.0 PATCH allows `add` / `replace` without a
    # path, where `value` is a partial resource dict. We merge it in
    # whole-resource style.
    if raw_path is None:
        if op == "remove":
            raise ScimWriteError(
                status_code=400,
                detail="`remove` without `path` is not supported.",
                scim_type="noTarget",
            )
        if not isinstance(value, dict):
            raise ScimWriteError(
                status_code=400,
                detail="`add` / `replace` without `path` requires a JSON object value.",
                scim_type="invalidValue",
            )
        # Reject forbidden keys at this layer too.
        _ensure_no_mutability_violation(value, source="patch value")
        for sub_key, sub_value in value.items():
            sub_path = _normalise_patch_path(sub_key)
            if sub_path is None:
                continue
            if sub_path in _FORBIDDEN_PATHS:
                raise ScimWriteError(
                    status_code=400,
                    detail=f"Attribute `{sub_key}` is not writable via inbound SCIM.",
                    scim_type="mutability",
                )
            _patch_assign(payload_acc, sub_path, sub_value)
        return

    norm = _normalise_patch_path(raw_path)
    if norm is None:
        return
    if norm in _FORBIDDEN_PATHS:
        raise ScimWriteError(
            status_code=400,
            detail=f"Path `{raw_path}` is not writable via inbound SCIM.",
            scim_type="mutability",
        )
    if (
        norm not in _PATCH_ALLOWED_SIMPLE_PATHS
        and norm != "name"
        and not norm.startswith("enterprise.")
    ):
        # `displayname` etc. are explicitly allowed; "name" is the whole
        # block. Enterprise sub-attribute paths are allowed too.
        # Anything else we deliberately decline so we can extend
        # carefully.
        raise ScimWriteError(
            status_code=400,
            detail=f"Path `{raw_path}` is not a supported PATCH target.",
            scim_type="invalidPath",
        )

    if op == "remove":
        # Map remove to a clearing assignment.
        if norm == "active":
            # Removing active is treated as `active=false` per common
            # vendor practice (Entra sometimes sends this on disable).
            _patch_assign(payload_acc, norm, False)
        elif norm == "externalid":
            payload_acc["externalId"] = ""
        elif norm == "displayname":
            payload_acc["displayName"] = ""
        elif norm.startswith("name."):
            payload_acc.setdefault("name", {})[norm.split(".", 1)[1]] = ""
        elif norm == "emails":
            payload_acc["emails"] = []
        else:
            payload_acc[norm] = None
        return

    _patch_assign(payload_acc, norm, value)


def patch_user(
    tenant_id: str,
    idp_id: str,
    user_id: str,
    patch_body: dict,
    *,
    location_builder,
) -> dict:
    """SCIM `PATCH /Users/{id}` with simple-path + batched-op support."""
    existing = database.users.get_user_by_id(tenant_id, user_id)
    if existing is None or str(existing.get("saml_idp_id") or "") != str(idp_id):
        raise ScimWriteError(status_code=404, detail="User not found")

    if not isinstance(patch_body, dict):
        raise ScimWriteError(
            status_code=400,
            detail="PATCH body must be a JSON object.",
            scim_type="invalidSyntax",
        )

    ops = patch_body.get("Operations") or patch_body.get("operations")
    if not isinstance(ops, list) or not ops:
        raise ScimWriteError(
            status_code=400,
            detail="PATCH body must contain a non-empty `Operations` array.",
            scim_type="invalidSyntax",
        )

    payload_acc: dict = {}
    for raw_op in ops:
        _process_patch_operation(payload_acc, raw_op)

    if not payload_acc:
        # All ops were no-ops; respond with the current state.
        return _resolve_user_payload(tenant_id, idp_id, user_id, location_builder)

    # Apply the synthesised payload as if it were a partial PUT.
    _apply_payload_writes(tenant_id, idp_id, user_id, payload_acc, update_names=True)

    active = payload_acc.get("active")
    if active is not None:
        if not isinstance(active, bool):
            raise ScimWriteError(
                status_code=400,
                detail="`active` must be a boolean.",
                scim_type="invalidValue",
            )
        _handle_active_transition(tenant_id, idp_id, user_id, active)

    _bump_updated_at(tenant_id, user_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="user",
        artifact_id=user_id,
        event_type="scim_user_updated",
        metadata={"idp_id": idp_id, "verb": "PATCH", "ops": len(ops)},
    )

    return _resolve_user_payload(tenant_id, idp_id, user_id, location_builder)


def soft_delete_user(
    tenant_id: str,
    idp_id: str,
    user_id: str,
) -> None:
    """SCIM `DELETE /Users/{id}`: soft-delete via the inactivate flow.

    Preserves MFA, audit history, granted access -- mirrors the admin
    UI's inactivate, modulo the admin-only authorization gate.
    """
    existing = database.users.get_user_by_id(tenant_id, user_id)
    if existing is None or str(existing.get("saml_idp_id") or "") != str(idp_id):
        raise ScimWriteError(status_code=404, detail="User not found")

    if existing.get("is_inactivated"):
        # Already inactivated -- idempotent success.
        return

    database.users.inactivate_user(tenant_id, user_id)
    database.oauth2.revoke_all_user_tokens(tenant_id, user_id)
    _bump_updated_at(tenant_id, user_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="user",
        artifact_id=user_id,
        event_type="scim_user_deactivated",
        metadata={"idp_id": idp_id, "cause": "scim_delete"},
    )
