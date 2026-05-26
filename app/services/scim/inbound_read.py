"""Read-only service functions for the inbound SCIM endpoint family.

The endpoint family at `/scim/v2/inbound/{idp_id}/Users` and `.../Groups`
returns directory state projected into SCIM 2.0 shape. These functions:

- Authorise based on the inbound SCIM context (the IdP id from the
  validated bearer token, not a `RequestingUser`).
- Defer to the iteration-2 database helpers in `database.users` /
  `database.groups` for the actual queries.
- Build SCIM payload dicts directly (rather than going through the
  outbound payload builder) -- the read side has subtly different
  needs around `id` vs `externalId` (we mint our own `id`; outbound
  uses WeftID's id as `externalId` since the SP mints the `id`).

The router converts these dicts into SCIM ListResponse / single
resource bodies and applies the `meta.location` URLs.

Activity tracking: NOT called here. `track_activity` records last
activity for a WeftID user, but inbound SCIM authenticates with a
token (no user). The token's `last_used_at` already records the
equivalent fact in `scim_inbound_tokens`.
"""

from __future__ import annotations

import database
from schemas.scim import (
    ENTERPRISE_USER_SCHEMA,
    GROUP_SCHEMA,
    USER_SCHEMA,
)


def _user_payload(user: dict) -> dict:
    """Project a WeftID user row into a SCIM User resource dict.

    Drops the `schemas` extension URN when no enterprise attributes are
    set (iteration 2 doesn't populate any yet). Iteration 3 will
    expand this once the IdP-attribute mirror pipeline is wired.
    """
    first = user.get("first_name")
    last = user.get("last_name")
    email = user.get("email")
    full = " ".join(p for p in (first, last) if p) or None
    active = not bool(user.get("is_inactivated") or user.get("is_anonymized"))

    payload: dict = {
        "schemas": [USER_SCHEMA],
        "id": str(user["id"]),
        "userName": email if email else str(user["id"]),
        "active": active,
    }

    name_obj: dict = {}
    if first:
        name_obj["givenName"] = first
    if last:
        name_obj["familyName"] = last
    if full:
        name_obj["formatted"] = full
    if name_obj:
        payload["name"] = name_obj
    if full:
        payload["displayName"] = full

    if email:
        payload["emails"] = [
            {"value": email, "type": "work", "primary": True},
        ]

    # `externalId` is the upstream-assigned id. Iteration 2 has no place
    # to store one yet (iteration 3 wires up `user_idp_attributes` /
    # NameID-mapping persistence), so we omit the field. We deliberately
    # do NOT round-trip WeftID's `id` into `externalId` -- that would
    # mislead clients into thinking we stored their externalId when we
    # haven't yet. Iteration 3 fills this in for real.
    return payload


def _user_with_metadata(user: dict, *, location: str, enterprise: dict | None = None) -> dict:
    """Attach SCIM `meta` and (optionally) enterprise extension to a user dict.

    Note: `users` doesn't currently carry an `updated_at` column. We use
    `created_at` for both `created` and `lastModified` until iteration 3
    introduces a mutation-time column (PATCH / PUT need it to be
    accurate, but iteration 2 is read-only so the conservative choice
    is to report `created_at` as the last-known mutation time).
    """
    payload = _user_payload(user)
    created_iso = user["created_at"].isoformat() if user.get("created_at") else None
    last_modified_iso = user["updated_at"].isoformat() if user.get("updated_at") else created_iso
    payload["meta"] = {
        "resourceType": "User",
        "location": location,
        "created": created_iso,
        "lastModified": last_modified_iso,
    }
    if enterprise:
        if ENTERPRISE_USER_SCHEMA not in payload["schemas"]:
            payload["schemas"].append(ENTERPRISE_USER_SCHEMA)
        payload[ENTERPRISE_USER_SCHEMA] = enterprise
    # Strip any None timestamps -- spec allows omitting these.
    payload["meta"] = {k: v for k, v in payload["meta"].items() if v is not None}
    return payload


def _member_display(member: dict) -> str | None:
    full = " ".join(p for p in (member.get("first_name"), member.get("last_name")) if p) or None
    if full:
        return full
    email = member.get("email")
    return str(email) if email else None


def _group_payload(group: dict, members: list[dict], *, members_base_url: str) -> dict:
    """Project a WeftID group row into a SCIM Group resource dict.

    `members_base_url` is the absolute URL of `/Users` for this IdP,
    used to build `$ref` values. Member `value` is the WeftID user
    id (which is also what SCIM `id` is on the User side).
    """
    member_entries: list[dict] = []
    for m in members:
        value = str(m["id"])
        entry: dict = {
            "value": value,
            "$ref": f"{members_base_url}/{value}",
            "type": "User",
        }
        display = _member_display(m)
        if display:
            entry["display"] = display
        member_entries.append(entry)

    return {
        "schemas": [GROUP_SCHEMA],
        "id": str(group["id"]),
        "displayName": group["name"],
        "members": member_entries,
    }


def _group_with_metadata(
    group: dict,
    members: list[dict],
    *,
    location: str,
    members_base_url: str,
) -> dict:
    payload = _group_payload(group, members, members_base_url=members_base_url)
    meta: dict = {"resourceType": "Group", "location": location}
    if group.get("created_at"):
        meta["created"] = group["created_at"].isoformat()
    if group.get("updated_at"):
        meta["lastModified"] = group["updated_at"].isoformat()
    payload["meta"] = meta
    return payload


# ---------------------------------------------------------------------------
# Public service-layer functions
# ---------------------------------------------------------------------------


def list_users(
    tenant_id: str,
    idp_id: str,
    *,
    user_name: str | None = None,
    external_id: str | None = None,
    start_index: int = 1,
    count: int = 100,
    location_builder=lambda user_id: f"Users/{user_id}",  # noqa: E731
) -> tuple[list[dict], int]:
    """Return (page_of_user_payloads, total_count) for one IdP.

    `location_builder(user_id) -> str` lets the router inject absolute
    URLs without forcing this layer to know about Request objects.
    """
    rows = database.users.list_users_for_idp(
        tenant_id,
        idp_id,
        user_name=user_name,
        external_id=external_id,
        start_index=start_index,
        count=count,
    )
    total = database.users.count_users_for_idp(
        tenant_id,
        idp_id,
        user_name=user_name,
        external_id=external_id,
    )
    payloads = [_user_with_metadata(r, location=location_builder(str(r["id"]))) for r in rows]
    return payloads, total


def get_user(
    tenant_id: str,
    idp_id: str,
    user_id: str,
    *,
    location: str,
) -> dict | None:
    """Return one user as a SCIM dict, or None if not bound to this IdP."""
    row = database.users.get_user_for_idp(tenant_id, idp_id, user_id)
    if row is None:
        return None
    return _user_with_metadata(row, location=location)


def list_groups(
    tenant_id: str,
    idp_id: str,
    *,
    display_name: str | None = None,
    start_index: int = 1,
    count: int = 100,
    group_location_builder=lambda group_id: f"Groups/{group_id}",  # noqa: E731
    members_base_url: str = "Users",
) -> tuple[list[dict], int]:
    """Return (page_of_group_payloads, total_count) for one IdP."""
    rows = database.groups.list_groups_for_idp(
        tenant_id,
        idp_id,
        display_name=display_name,
        start_index=start_index,
        count=count,
    )
    total = database.groups.count_groups_for_idp(
        tenant_id,
        idp_id,
        display_name=display_name,
    )
    payloads = []
    for group_row in rows:
        members = database.groups.list_group_members_for_scim(tenant_id, str(group_row["id"]))
        payloads.append(
            _group_with_metadata(
                group_row,
                members,
                location=group_location_builder(str(group_row["id"])),
                members_base_url=members_base_url,
            )
        )
    return payloads, total


def get_group(
    tenant_id: str,
    idp_id: str,
    group_id: str,
    *,
    location: str,
    members_base_url: str,
) -> dict | None:
    """Return one IdP group as a SCIM dict, or None if not bound to this IdP."""
    row = database.groups.get_group_for_idp(tenant_id, idp_id, group_id)
    if row is None:
        return None
    members = database.groups.list_group_members_for_scim(tenant_id, str(row["id"]))
    return _group_with_metadata(
        row,
        members,
        location=location,
        members_base_url=members_base_url,
    )
