"""OIDC upstream attribute mirroring.

Parallel to ``services.users.attributes.apply_idp_attributes`` /
``scrub_canonical_matches_mirror`` for the consuming (relying-party)
direction of OIDC. The only difference is the IdP ownership check and the
snapshot table: ``apply_oidc_idp_attributes`` validates ``idp_id`` against
``oidc_idp_connections`` and writes ``user_oidc_idp_attributes`` (instead of
``saml_identity_providers`` / ``user_idp_attributes``).

The canonical ``user_attributes`` write path is identical: for each key the
tenant has ``enabled=true`` AND ``mirror_from_idp=true``, upsert the
serialized value with ``source='idp'``; emit a single
``user_profile_updated`` event with ``cause=idp_mirror`` when anything
changed.

The disconnect scrub is likewise a parallel of
``scrub_canonical_matches_mirror``: it deletes canonical rows whose value
still equals the OIDC IdP's last-mirrored snapshot value, emitting
``cause=idp_disconnect_scrub``.
"""

from __future__ import annotations

import logging

import database
from constants.user_attributes import is_standard_attribute, serialize
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError

logger = logging.getLogger(__name__)


def apply_oidc_idp_attributes(
    tenant_id: str,
    user_id: str,
    idp_id: str,
    attributes: dict[str, str],
    *,
    actor_user_id: str,
) -> None:
    """Apply an OIDC IdP login's attribute set to both storage spaces.

    1. Validate ``idp_id`` belongs to ``tenant_id`` (against
       ``oidc_idp_connections``).
    2. Replace the user's OIDC IdP-mirror snapshot for that connection
       atomically.
    3. For each (key, value) where the tenant has ``enabled=true`` AND
       ``mirror_from_idp=true``, upsert ``user_attributes`` with the
       serialized value.
    4. Emit a single ``user_profile_updated`` event with
       ``cause=idp_mirror`` when one or more canonical values changed.

    Both writes happen inside one ``database.session()`` so observers never
    see a partial state.

    Unknown attribute keys (not in the standard registry) are dropped
    silently from both writes -- the per-connection claim_mapping is expected
    to filter, but defence in depth never hurts.
    """
    # 1. Tenant-connection ownership check (defence in depth at the service
    # boundary; the per-connection claim_mapping JSON is supposed to be in
    # this tenant already, but we verify before writing rows that reference
    # idp_id).
    connection = database.oidc_upstream.get_connection(tenant_id, idp_id)
    if connection is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
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
        except ValueError, ValidationError:
            # Skip malformed values silently -- the OIDC login flow must not
            # fail because one attribute is wrong. The mirror table simply
            # won't carry it.
            continue

    changes: dict[str, str] = {}

    with database.session(tenant_id=tenant_id) as cur:
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

        # Replace the OIDC IdP-mirror snapshot for this connection.
        if serialized_attributes:
            cur.execute(
                """
                delete from user_oidc_idp_attributes
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
                delete from user_oidc_idp_attributes
                where user_id = %(user_id)s and idp_id = %(idp_id)s
                """,
                {"user_id": user_id, "idp_id": idp_id},
            )

        for key, value in serialized_attributes.items():
            cur.execute(
                """
                insert into user_oidc_idp_attributes (
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

        # Mirror enabled+mirror_from_idp keys into user_attributes.
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


def scrub_oidc_canonical_matches_mirror(
    *,
    tenant_id: str,
    idp_id: str,
    actor_user_id: str,
    user_id: str | None = None,
) -> int:
    """Delete canonical ``user_attributes`` rows whose value still equals an
    OIDC connection's last-mirrored snapshot value.

    Used when a user's relationship to ``idp_id`` ends (the connection is
    deleted, or the user is disconnected), so attributes that only ever flowed
    in from that connection stop being emitted in assertions.

    Canonical rows that have diverged from the mirror snapshot (because the
    user or an admin edited them after the mirror write) are left alone, since
    those carry independent provenance. Emits one ``user_profile_updated``
    event per affected user with ``cause: idp_disconnect_scrub`` listing the
    cleared keys. Returns the total number of canonical rows deleted.

    When ``user_id`` is given the scrub is confined to that single user;
    otherwise every user mirrored from ``idp_id`` is scrubbed.
    """
    params: dict[str, str] = {"idp_id": idp_id, "tenant_id": tenant_id}
    user_filter = ""
    if user_id is not None:
        user_filter = "and ua.user_id = %(user_id)s"
        params["user_id"] = user_id

    with database.session(tenant_id=tenant_id) as cur:
        cur.execute(
            f"""
            delete from user_attributes ua
            using user_oidc_idp_attributes uia
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
