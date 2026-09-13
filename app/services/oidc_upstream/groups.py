"""OIDC upstream group claim handling.

Reads the connection's ``group_claim_source`` from the validated claims
(ID token merged with userinfo) and performs a full sync of the user's
OIDC-sourced IdP groups, mirroring the SAML group-assertion behaviour.

Semantics:

- **Base group first.** Every user who signs in through a connection is put
  in that connection's base (umbrella) group, whether or not a group claim
  is configured. Claim-discovered groups are wired beneath it.
- **Present claim (even an empty list) is authoritative.** A full sync runs:
  new groups are created as ``idp``-type groups, the user is added to the
  groups in the claim and removed from this connection's groups that are
  no longer listed.
- **Absent claim is "no information".** Nothing changes. This is deliberate:
  a provider that drops the claim (misconfigured scope, Entra group overage)
  must not silently strip the user's memberships.
- **Entra overage** (``_claim_names`` naming the group claim) is detected
  and recorded as an ``oidc_group_claim_overage`` audit event so the admin
  can see why groups stopped syncing for that user.

Value shapes accepted for the claim:

- a JSON array of strings: ``["admins", "engineering"]``
- a JSON array of objects, with the group name under
  ``group_claim_name_key`` (default ``name``):
  ``[{"id": "1", "name": "admins"}, ...]``
- a bare string (one group)

Entra's ``groups`` claim carries directory object ids (GUIDs). Those are
used verbatim as group names; resolving them to display names needs
Microsoft Graph and is out of scope here.
"""

from __future__ import annotations

import logging

import services.groups as groups_service
from services.event_log import log_event

logger = logging.getLogger(__name__)

# Key read from each object when the claim is a list of objects and the
# connection does not name one.
DEFAULT_NAME_KEY = "name"

# groups.name has a 200-character CHECK; longer values are dropped rather
# than truncated so two distinct upstream groups never collapse into one.
MAX_GROUP_NAME_LENGTH = 200

# Upper bound on groups honoured from a single sign-in. Entra caps the claim
# at 200 (then switches to overage); this is a safety valve for generic IdPs.
MAX_GROUPS_PER_SIGN_IN = 500

# Entra's overage marker: when a user is in more groups than fit in the token,
# the group claim is omitted and this claim names it instead.
OVERAGE_MARKER_CLAIM = "_claim_names"

SYNC_SOURCE = "oidc_authentication"


def extract_group_names(
    claims: dict,
    claim_name: str,
    name_key: str | None = None,
) -> list[str] | None:
    """Return the group names carried by ``claims[claim_name]``.

    Returns ``None`` when the claim is absent (or ``null``, or of an
    unsupported shape) so the caller can distinguish "no information" from
    "no groups". Names are stripped, de-duplicated (order preserved), and
    over-long or empty entries are dropped.
    """
    if not claim_name or claim_name not in claims:
        return None

    raw = claims[claim_name]
    if raw is None:
        return None

    if isinstance(raw, str):
        values: list = [raw]
    elif isinstance(raw, list):
        values = raw
    else:
        logger.warning(
            "OIDC group claim %r has unsupported shape %s; ignoring",
            claim_name,
            type(raw).__name__,
        )
        return None

    key = (name_key or "").strip() or DEFAULT_NAME_KEY

    names: list[str] = []
    seen: set[str] = set()
    for item in values:
        candidate = item.get(key) if isinstance(item, dict) else item
        # bool is an int subclass; never treat true/false as a group name.
        if isinstance(candidate, bool):
            continue
        if isinstance(candidate, int):
            candidate = str(candidate)
        if not isinstance(candidate, str):
            continue
        candidate = candidate.strip()
        if not candidate or len(candidate) > MAX_GROUP_NAME_LENGTH:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        names.append(candidate)
        if len(names) >= MAX_GROUPS_PER_SIGN_IN:
            logger.warning(
                "OIDC group claim %r exceeded %d entries; extra groups ignored",
                claim_name,
                MAX_GROUPS_PER_SIGN_IN,
            )
            break

    return names


def has_group_claim_overage(claims: dict, claim_name: str) -> bool:
    """True when the provider signalled group overage for ``claim_name``.

    Entra omits the ``groups`` claim when the user belongs to more groups
    than fit in the token and instead emits ``_claim_names`` naming the
    omitted claim (with ``_claim_sources`` pointing at a Graph endpoint).
    """
    marker = claims.get(OVERAGE_MARKER_CLAIM)
    return isinstance(marker, dict) and claim_name in marker


def sync_groups_from_claims(
    tenant_id: str,
    user_id: str,
    user_email: str,
    connection: dict,
    claims: dict,
) -> dict | None:
    """Put the user in the connection's base group and sync claim groups.

    Returns the sync result dict (``added``/``removed``/``created``) when a
    sync ran, or ``None`` when no group claim is configured, the claim was
    absent, or the provider signalled overage.

    Failures propagate: group membership gates application access, so a
    sync that cannot complete must fail the sign-in rather than leave stale
    memberships in place.
    """
    connection_id = str(connection["id"])
    idp_name = connection["name"]

    groups_service.ensure_user_in_base_group(
        tenant_id,
        user_id,
        user_email,
        connection_id,
        idp_name,
        source="oidc",
    )

    claim_name = (connection.get("group_claim_source") or "").strip()
    if not claim_name:
        return None

    if has_group_claim_overage(claims, claim_name):
        logger.warning(
            "OIDC connection %s: provider omitted group claim %r for user %s (overage)",
            connection_id,
            claim_name,
            user_id,
        )
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="oidc_idp_connection",
            artifact_id=connection_id,
            event_type="oidc_group_claim_overage",
            metadata={
                "idp_name": idp_name,
                "user_id": user_id,
                "claim": claim_name,
            },
        )
        return None

    group_names = extract_group_names(claims, claim_name, connection.get("group_claim_name_key"))
    if group_names is None:
        logger.info(
            "OIDC connection %s: group claim %r absent for user %s; memberships unchanged",
            connection_id,
            claim_name,
            user_id,
        )
        return None

    return groups_service.sync_user_idp_groups(
        tenant_id=tenant_id,
        user_id=user_id,
        user_email=user_email,
        idp_id=connection_id,
        idp_name=idp_name,
        group_names=group_names,
        source="oidc",
        sync_source=SYNC_SOURCE,
    )
